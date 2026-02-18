from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from tree_sitter_languages import get_parser


_JAVA_PARSER = get_parser("java")


ENTRY_ANN_HTTP = {
    "RequestMapping",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
}
ENTRY_ANN_MQ = {"KafkaListener", "JmsListener", "RabbitListener", "SqsListener", "Consumer"}
ENTRY_ANN_JOB = {"Scheduled"}

AUTH_ANN = {"PreAuthorize", "Secured", "RolesAllowed"}

VALIDATION_ANN = {"Valid", "NotNull", "NotEmpty", "NotBlank", "Size", "Pattern", "Min", "Max"}

RATE_ANN = {"RateLimiter", "Bulkhead", "TimeLimiter", "CircuitBreaker"}

AUDIT_PAT = re.compile(r"\b(audit|securityLog|secLog)\b", re.IGNORECASE)
SANITIZE_PAT = re.compile(r"\b(escape|encode|sanitize|htmlEscape)\b")
VALIDATE_CALL_PAT = re.compile(r"\b(validate|requireNonNull|checkArgument)\b")

SECRET_WORDS_PAT = re.compile(r"\b(password|passwd|token|secret|apiKey|apikey|creditCard)\b", re.IGNORECASE)
LOG_PAT = re.compile(r"\b(log\.info|log\.debug|log\.warn|log\.error|logger\.)")
SERIALIZE_PAT = re.compile(r"\b(objectMapper\.writeValueAsString|toJson|serialize)\b")

ETI_LEAK_PAT = re.compile(r"(getMessage\(\)|printStackTrace\(\))")


@dataclass(frozen=True)
class EntryPoint:
    method_id: str
    entry_type: str  # http|mq|job|other
    has_auth: bool
    has_validation: bool
    param_risk: str  # low|stringy|untyped|binary
    entropy_level: str  # low|medium|high|very_high


@dataclass(frozen=True)
class Sink:
    method_id: str
    kind: str  # db|fs|http|other
    privileged: bool


def _node_text(src: bytes, node) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _find_children(node, type_name: str) -> list:
    out = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == type_name:
            out.append(n)
        for ch in n.children:
            stack.append(ch)
    return out


def _first_child(node, type_name: str):
    for ch in node.children:
        if ch.type == type_name:
            return ch
    return None


def _extract_identifier(src: bytes, node) -> str:
    # Heuristic fallback: first identifier token in subtree in source-order.
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "identifier":
            return _node_text(src, n)
        for ch in reversed(n.children):
            stack.append(ch)
    return ""

def _field_text(src: bytes, node, field_name: str) -> str:
    ch = node.child_by_field_name(field_name)
    if not ch:
        return ""
    return _node_text(src, ch).strip()


def _annotation_name(src: bytes, ann_node) -> str:
    name = _field_text(src, ann_node, "name") or _extract_identifier(src, ann_node)
    if not name:
        return ""
    return name.split(".")[-1]


def _extract_annotations(src: bytes, node) -> set[str]:
    anns = set()
    for ann_type in ("annotation", "marker_annotation", "single_element_annotation"):
        for ann in _find_children(node, ann_type):
            name = _annotation_name(src, ann)
            if name:
                anns.add(name)
    return anns


def _extract_param_types(src: bytes, method_node) -> list[str]:
    """Извлекает текстовые представления типов параметров метода."""
    types = []
    params = _first_child(method_node, "formal_parameters")
    if not params:
        return types
    for param in _find_children(params, "formal_parameter"):
        tnode = param.child_by_field_name("type")
        if tnode:
            types.append(_node_text(src, tnode).strip())
    return types


def _entry_type_from_annotations(anns: set[str]) -> str:
    if anns & ENTRY_ANN_HTTP:
        return "http"
    if anns & ENTRY_ANN_MQ:
        return "mq"
    if anns & ENTRY_ANN_JOB:
        return "job"
    return "other"


def _param_risk(param_types: list[str]) -> tuple[str, str]:
    # Returns (risk, entropy_level)
    if not param_types:
        return "low", "low"
    joined = " ".join(param_types)
    if "InputStream" in joined or "byte[" in joined or "byte[]" in joined:
        return "binary", "very_high"
    if any(t.strip().endswith("Object") for t in param_types) or "Map" in joined or "JsonNode" in joined:
        return "untyped", "high"
    if "String" in joined:
        return "stringy", "medium"
    return "low", "low"


def _has_validation(src: bytes, method_node, anns: set[str]) -> bool:
    if anns & VALIDATION_ANN:
        return True
    body = _first_child(method_node, "block")
    if not body:
        return False
    text = _node_text(src, body)
    return bool(VALIDATE_CALL_PAT.search(text) or SANITIZE_PAT.search(text))


def _has_auth(anns: set[str]) -> bool:
    return bool(anns & AUTH_ANN)


def _method_complexity(src: bytes, method_node) -> int:
    # Very rough cognitive complexity approximation:
    # +1 for each control structure, +nesting level.
    body = _first_child(method_node, "block")
    if not body:
        return 0

    control_types = {
        "if_statement",
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "switch_statement",
        "switch_expression",
        "catch_clause",
        "conditional_expression",
    }

    def walk(node, depth: int) -> int:
        score = 0
        for ch in node.children:
            nd = depth
            if ch.type in control_types:
                score += 1 + depth
                nd = depth + 1
            score += walk(ch, nd)
        return score

    return walk(body, 0)


def _method_calls(src: bytes, method_node) -> list[str]:
    body = _first_child(method_node, "block")
    if not body:
        return []
    names = []
    for inv in _find_children(body, "method_invocation"):
        name = _field_text(src, inv, "name") or _field_text(src, inv, "member")
        if not name:
            # Fallback: prefer last identifier in subtree.
            ids = []
            stack = [inv]
            while stack:
                n = stack.pop()
                if n.type == "identifier":
                    ids.append(_node_text(src, n))
                for ch in n.children:
                    stack.append(ch)
            if ids:
                name = ids[-1]
        if name:
            names.append(name)
    return names


def _class_kind_from_decl(src: bytes, decl_node) -> str:
    if decl_node.type == "interface_declaration":
        return "interface"
    if decl_node.type in {"enum_declaration", "record_declaration"}:
        return "concrete"
    if decl_node.type == "class_declaration":
        modifiers = decl_node.child_by_field_name("modifiers")
        if modifiers and "abstract" in _node_text(src, modifiers).split():
            return "abstract"
        # Fallback for parser variants where modifiers are not exposed as field.
        if "abstract" in _node_text(src, decl_node).split():
            return "abstract"
    return "concrete"


def _collect_type_decls(src: bytes, root_node) -> list[dict]:
    decls: list[dict] = []
    for typ in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
        for n in _find_children(root_node, typ):
            name = _field_text(src, n, "name") or _extract_identifier(src, n)
            if not name:
                continue
            decls.append(
                {
                    "name": name,
                    "start": n.start_byte,
                    "end": n.end_byte,
                    "kind": _class_kind_from_decl(src, n),
                }
            )
    decls.sort(key=lambda d: (d["start"], -d["end"]))
    return decls


def _enclosing_type_for_method(method_node, type_decls: list[dict]) -> tuple[str, str]:
    method_start = method_node.start_byte
    method_end = method_node.end_byte
    containers = [d for d in type_decls if d["start"] <= method_start and method_end <= d["end"]]
    if not containers:
        return "Unknown", "concrete"
    containers.sort(key=lambda d: (d["start"], -d["end"]))
    return ".".join(d["name"] for d in containers), containers[-1]["kind"]


def _resolve_placeholder_edges(edges: dict[str, set[str]], method_defs_by_name: dict[str, list[str]]) -> dict[str, set[str]]:
    resolved: dict[str, set[str]] = {}
    for src, dsts in edges.items():
        out = set()
        for dst in dsts:
            if dst.startswith("name:"):
                name = dst.split(":", 1)[1]
                # Prefer bounded expansion to avoid blow-ups.
                cands = method_defs_by_name.get(name, [])
                for mid in cands[:20]:
                    out.add(mid)
            else:
                out.add(dst)
        resolved[src] = out
    return resolved


def _package_name(src: bytes, root_node) -> str:
    for n in _find_children(root_node, "package_declaration"):
        txt = _node_text(src, n)
        m = re.search(r"package\s+([a-zA-Z0-9_.]+)\s*;", txt)
        if m:
            return m.group(1)
    return ""


@dataclass
class JavaGraph:
    # method_id -> called method_ids
    edges: dict[str, set[str]]
    # method_id -> attributes
    method_complexity: dict[str, int]
    method_flags: dict[str, dict]
    entrypoints: list[EntryPoint]
    sinks: list[Sink]
    catch_blocks: list[str]
    security_constructs: list[dict]

    @property
    def nodes_count(self) -> int:
        nodes = set(self.edges.keys())
        for s in self.edges.values():
            nodes |= s
        return len(nodes)

    @property
    def edges_count(self) -> int:
        return sum(len(v) for v in self.edges.values())

    def distance_from_entrypoints(self, *, max_depth: int) -> dict[str, int]:
        # multi-source BFS
        q = []
        dist: dict[str, int] = {}
        for ep in self.entrypoints:
            dist[ep.method_id] = 0
            q.append(ep.method_id)
        head = 0
        while head < len(q):
            cur = q[head]
            head += 1
            d = dist[cur]
            if d >= max_depth:
                continue
            for nxt in self.edges.get(cur, ()):
                if nxt not in dist:
                    dist[nxt] = d + 1
                    q.append(nxt)
        return dist

    def defense_in_depth_paths(self, *, max_depth: int) -> dict:
        # layers bitmask: 6 categories
        # 0 auth, 1 authz, 2 validation, 3 sanitize, 4 rate, 5 audit
        def layers_mask(mid: str) -> int:
            f = self.method_flags.get(mid, {})
            m = 0
            if f.get("auth"):
                m |= 1 << 0
            if f.get("authz"):
                m |= 1 << 1
            if f.get("validation"):
                m |= 1 << 2
            if f.get("sanitize"):
                m |= 1 << 3
            if f.get("rate"):
                m |= 1 << 4
            if f.get("audit"):
                m |= 1 << 5
            return m

        sink_set = {s.method_id for s in self.sinks}
        # BFS over (method, mask)
        from collections import deque

        dq = deque()
        seen = set()
        for ep in self.entrypoints:
            m = layers_mask(ep.method_id)
            st = (ep.method_id, m, 0)
            dq.append(st)
            seen.add((ep.method_id, m))

        paths_analyzed = 0
        best_ratio = None
        best_detail = None

        while dq:
            mid, mask, depth = dq.popleft()
            if mid in sink_set:
                paths_analyzed += 1
                uniq = bin(mask).count("1")
                ratio = uniq / 6.0
                if best_ratio is None or ratio < best_ratio:
                    best_ratio = ratio
                    best_detail = {"sink": mid, "layers": uniq, "ratio": ratio, "depth": depth}
                # Do not stop; there might be even weaker paths.
            if depth >= max_depth:
                continue
            for nxt in self.edges.get(mid, ()):
                nmask = mask | layers_mask(nxt)
                key = (nxt, nmask)
                if key in seen:
                    continue
                seen.add(key)
                dq.append((nxt, nmask, depth + 1))

        return {
            "system_min_ratio": best_ratio,
            "paths_analyzed": paths_analyzed,
            "min_path": best_detail,
        }

    def min_distance_unauth_to_privileged(self, *, max_depth: int) -> int | None:
        unauth = [ep.method_id for ep in self.entrypoints if not ep.has_auth]
        priv = {s.method_id for s in self.sinks if s.privileged}
        if not unauth or not priv:
            return None
        from collections import deque

        dq = deque()
        dist = {}
        for u in unauth:
            dist[u] = 0
            dq.append(u)
        while dq:
            cur = dq.popleft()
            d = dist[cur]
            if cur in priv:
                return d
            if d >= max_depth:
                continue
            for nxt in self.edges.get(cur, ()):
                if nxt in dist:
                    continue
                dist[nxt] = d + 1
                dq.append(nxt)
        return None

    def path_security_parity(self, *, max_depth: int) -> dict:
        # Security parity for a sensitive operation: compare weakest vs strongest
        # path in terms of *presence* of controls (auth/authz/validation), not count.
        # We model this as a 3-bit mask to keep state space bounded and avoid path-length bias.
        def mask3(mid: str) -> int:
            f = self.method_flags.get(mid, {})
            m = 0
            if f.get("auth"):
                m |= 1 << 0
            if f.get("authz"):
                m |= 1 << 1
            if f.get("validation"):
                m |= 1 << 2
            return m

        sink_set = {s.method_id for s in self.sinks}
        from collections import deque

        dq = deque()
        seen = set()
        for ep in self.entrypoints:
            m = mask3(ep.method_id)
            dq.append((ep.method_id, m, 0))
            seen.add((ep.method_id, m))

        per_sink = {s.method_id: {"min": None, "max": None} for s in self.sinks}

        while dq:
            mid, mask, depth = dq.popleft()
            if mid in sink_set:
                cur = per_sink[mid]
                sc = bin(mask).count("1")
                cur["min"] = sc if cur["min"] is None else min(cur["min"], sc)
                cur["max"] = sc if cur["max"] is None else max(cur["max"], sc)
            if depth >= max_depth:
                continue
            for nxt in self.edges.get(mid, ()):
                nmask = mask | mask3(nxt)
                key = (nxt, nmask)
                if key in seen:
                    continue
                seen.add(key)
                dq.append((nxt, nmask, depth + 1))

        worst_ratio = 1.0
        worst = None
        for sid, mm in per_sink.items():
            if mm["min"] is None or mm["max"] is None or mm["max"] == 0:
                continue
            ratio = mm["min"] / mm["max"]
            if ratio < worst_ratio:
                worst_ratio = ratio
                worst = {"operation": sid, "min_score": mm["min"], "max_score": mm["max"], "ratio": ratio}

        return {"system_min_ratio": worst_ratio if worst else 1.0, "worst_operation": worst}

    def fail_safe_score(self) -> dict:
        # Analyze catch blocks text.
        total = len(self.catch_blocks)
        if total == 0:
            return {"FSS": 1.0, "catches_total": 0, "fail_closed": 0, "fail_open": 0, "ambiguous": 0}
        fail_closed = 0
        fail_open = 0
        ambiguous = 0
        empty = 0
        for body in self.catch_blocks:
            stripped = re.sub(r"\s+", "", body)
            if stripped in {"{}", "{/* */}", "{//}"}:
                empty += 1
                fail_open += 1
                continue
            if "throw" in body:
                fail_closed += 1
            elif re.search(r"return\s+(true|false|0|null)\b", body):
                ambiguous += 1
            else:
                ambiguous += 1
        fss = (fail_closed / total) if total else 1.0
        return {
            "FSS": fss,
            "catches_total": total,
            "fail_closed": fail_closed,
            "fail_open": fail_open,
            "ambiguous": ambiguous,
            "empty_catches": empty,
            "notes": ["Heuristic: any empty catch counts as fail-open; throw counts as fail-closed."],
        }

    def tainted_path_complexity(self, *, max_depth: int) -> dict:
        # Count max consecutive hops without validation/sanitization on any path from entry to sink.
        sinks = {s.method_id for s in self.sinks}
        from collections import deque

        def cleans(mid: str) -> bool:
            f = self.method_flags.get(mid, {})
            return bool(f.get("validation") or f.get("sanitize"))

        dq = deque()
        seen = set()
        max_run = 0
        hits = 0
        for ep in self.entrypoints:
            run = 0 if cleans(ep.method_id) else 1
            dq.append((ep.method_id, run, 0))
            seen.add((ep.method_id, run))
        while dq:
            mid, run, depth = dq.popleft()
            if mid in sinks:
                hits += 1
                if run > max_run:
                    max_run = run
            if depth >= max_depth:
                continue
            for nxt in self.edges.get(mid, ()):
                nrun = 0 if cleans(nxt) else (run + 1)
                key = (nxt, nrun)
                if key in seen:
                    continue
                seen.add(key)
                dq.append((nxt, nrun, depth + 1))
        return {"TPC_max_consecutive_unsafe_hops": max_run, "sink_reaches": hits, "notes": ["Heuristic taint: reset on any validation/sanitization flag."]}

    def error_transparency_index(self) -> dict:
        total = len(self.catch_blocks)
        if total == 0:
            return {"ETI": 0.0, "catches_total": 0, "leaks": 0, "swallowed": 0}
        leaks = 0
        swallowed = 0
        for body in self.catch_blocks:
            stripped = re.sub(r"\s+", "", body)
            if stripped == "{}":
                swallowed += 1
            if ETI_LEAK_PAT.search(body) and ("return" in body or "ResponseEntity" in body):
                leaks += 1
        return {"ETI": leaks / total, "catches_total": total, "leaks": leaks, "swallowed": swallowed}

    def secret_flow_analysis(self) -> dict:
        # Extremely rough: count lines where "secret" words co-occur with logging or serialization.
        total = 0
        leaks = 0
        samples = []
        for mid, f in self.method_flags.items():
            text = f.get("body_text") or ""
            if not text:
                continue
            for line in text.splitlines():
                if not SECRET_WORDS_PAT.search(line):
                    continue
                total += 1
                if LOG_PAT.search(line) or SERIALIZE_PAT.search(line):
                    leaks += 1
                    if len(samples) < 20:
                        samples.append({"method": mid, "line": line.strip()[:200]})
        return {"SFA": (leaks / total) if total else 0.0, "secret_mentions": total, "leak_lines": leaks, "sample": samples}

    def trust_chain_depth(self, *, max_depth: int) -> dict:
        # Approximation: from entrypoints with auth, how deep to sinks without seeing another auth/authz check.
        sinks = {s.method_id for s in self.sinks}
        from collections import deque

        def is_auth(mid: str) -> bool:
            f = self.method_flags.get(mid, {})
            return bool(f.get("auth") or f.get("authz"))

        dq = deque()
        seen = set()
        max_hops = 0
        for ep in self.entrypoints:
            if not ep.has_auth:
                continue
            dq.append((ep.method_id, 0, 0))  # (mid, hops_since_last_auth, depth)
            seen.add((ep.method_id, 0))
        while dq:
            mid, hops, depth = dq.popleft()
            if mid in sinks:
                if hops > max_hops:
                    max_hops = hops
            if depth >= max_depth:
                continue
            for nxt in self.edges.get(mid, ()):
                nhops = 0 if is_auth(nxt) else hops + 1
                key = (nxt, nhops)
                if key in seen:
                    continue
                seen.add(key)
                dq.append((nxt, nhops, depth + 1))
        return {"TCPD_max_hops_after_last_auth": max_hops, "notes": ["Heuristic: resets on any auth/authz flag in method."]}

    def coupling_summary(self) -> dict:
        out_deg = [len(v) for v in self.edges.values()]
        avg = (sum(out_deg) / len(out_deg)) if out_deg else 0.0
        return {"avg_out_degree": avg, "methods": len(out_deg)}

    def complexity_summary(self) -> dict:
        vals = list(self.method_complexity.values())
        avg = (sum(vals) / len(vals)) if vals else 0.0
        return {"avg_cognitive": avg, "methods": len(vals)}

    def abstraction_summary(self) -> dict:
        # method_flags stores class_kind, is_abstract maybe.
        concrete = 0
        total = 0
        for f in self.method_flags.values():
            ck = f.get("class_kind")
            if ck:
                total += 1
                if ck == "concrete":
                    concrete += 1
        ratio = (concrete / total) if total else 1.0
        return {"concrete_ratio": ratio, "samples": total}

    def export_topology(self, *, limit_nodes: int, limit_edges: int) -> dict:
        nodes = set(self.edges.keys())
        for s in self.edges.values():
            nodes |= s
        nodes_l = list(nodes)[:limit_nodes]
        node_set = set(nodes_l)
        edges_l = []
        for src, dsts in self.edges.items():
            if src not in node_set:
                continue
            for dst in dsts:
                if dst not in node_set:
                    continue
                edges_l.append([src, dst])
                if len(edges_l) >= limit_edges:
                    break
            if len(edges_l) >= limit_edges:
                break
        ep_ids = [ep.method_id for ep in self.entrypoints if ep.method_id in node_set]
        sink_ids = [s.method_id for s in self.sinks if s.method_id in node_set]

        return {
            "nodes": nodes_l,
            "edges": edges_l,
            "entrypoint_ids": ep_ids,
            "sink_ids": sink_ids,
        }


def build_java_graph(repo_dir: Path, *, max_files: int | None) -> JavaGraph:
    method_defs_by_name: dict[str, list[str]] = {}
    method_complexity: dict[str, int] = {}
    method_flags: dict[str, dict] = {}
    entrypoints: list[EntryPoint] = []
    sinks: list[Sink] = []
    edges: dict[str, set[str]] = {}
    catch_blocks: list[str] = []
    security_constructs: list[dict] = []

    files = []
    for root, dirs, fns in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "target", "build", ".gradle", ".idea"}]
        for fn in fns:
            if fn.endswith(".java"):
                files.append(Path(root) / fn)
    if max_files is not None:
        files = files[:max_files]

    def is_test_file(path: Path) -> bool:
        parts = [p.lower() for p in path.parts]
        if "src" in parts and "test" in parts:
            return True
        if "test" in parts or "tests" in parts:
            return True
        return False

    for path in files:
        is_test = is_test_file(path)
        try:
            src = path.read_bytes()
        except OSError:
            continue

        try:
            tree = _JAVA_PARSER.parse(src)
        except Exception:
            # A single malformed file must not abort the whole repository scan.
            continue
        root = getattr(tree, "root_node", None)
        if root is None:
            continue
        pkg = _package_name(src, root)
        type_decls = _collect_type_decls(src, root)

        # methods
        for m in _find_children(root, "method_declaration"):
            name = _field_text(src, m, "name") or _extract_identifier(src, m)
            if not name:
                continue
            cls, class_kind = _enclosing_type_for_method(m, type_decls)
            # Build method id
            params = _extract_param_types(src, m)
            sig = ",".join(p.strip() for p in params)
            mid = f"{pkg}.{cls}#{name}({sig})".strip(".")

            anns = _extract_annotations(src, m)
            entry_type = _entry_type_from_annotations(anns)
            has_auth = _has_auth(anns)
            has_val = _has_validation(src, m, anns)
            risk, entropy = _param_risk(params)

            if entry_type != "other":
                entrypoints.append(
                    EntryPoint(
                        method_id=mid,
                        entry_type=entry_type,
                        has_auth=has_auth,
                        has_validation=has_val,
                        param_risk=risk if risk in {"stringy", "untyped"} else "low",
                        entropy_level=entropy,
                    )
                )
            # flags
            body = _first_child(m, "block")
            body_text = _node_text(src, body) if body else ""
            flags = {
                "auth": has_auth,
                "authz": bool(anns & {"PreAuthorize", "Secured", "RolesAllowed"}),
                "validation": has_val,
                "sanitize": bool(SANITIZE_PAT.search(body_text)),
                "rate": bool(anns & RATE_ANN),
                "audit": bool(AUDIT_PAT.search(body_text)),
                "body_text": body_text[:20000],  # cap
                "class_kind": "concrete" if class_kind == "concrete" else "abstract",
                "is_test": is_test,
                "rel_path": str(path.relative_to(repo_dir)),
            }
            method_flags[mid] = flags

            # security constructs for SRP
            symbol = cls.rsplit(".", 1)[-1]
            if flags["authz"]:
                security_constructs.append({"kind": "authz", "symbol": symbol})
            if flags["validation"]:
                security_constructs.append({"kind": "validation", "symbol": symbol})
            if flags["sanitize"]:
                security_constructs.append({"kind": "sanitize", "symbol": symbol})

            # complexity + calls
            method_complexity[mid] = _method_complexity(src, m)
            calls = _method_calls(src, m)
            edges.setdefault(mid, set())
            for c in calls:
                # Resolve later: store as placeholder "name:<c>"
                edges[mid].add(f"name:{c}")

            # catch blocks
            for cc in _find_children(m, "catch_clause"):
                block = _first_child(cc, "block")
                if block:
                    catch_blocks.append(_node_text(src, block))

            # naive sinks detection from body text
            if body_text:
                if re.search(r"\b(update|delete|save|persist|merge|remove|executeUpdate)\b", body_text):
                    sinks.append(Sink(method_id=mid, kind="db", privileged=True))
                elif re.search(r"\b(Files\.write|FileOutputStream|PrintWriter)\b", body_text):
                    sinks.append(Sink(method_id=mid, kind="fs", privileged=True))
                elif re.search(r"\b(RestTemplate|WebClient|HttpClient|OkHttpClient)\b", body_text):
                    sinks.append(Sink(method_id=mid, kind="http", privileged=False))

            # Index method defs by simple name
            method_defs_by_name.setdefault(name, []).append(mid)

    # Resolve placeholder edges "name:foo" into method ids (approx).
    resolved = _resolve_placeholder_edges(edges, method_defs_by_name)

    return JavaGraph(
        edges=resolved,
        method_complexity=method_complexity,
        method_flags=method_flags,
        entrypoints=entrypoints,
        sinks=sinks,
        catch_blocks=catch_blocks,
        security_constructs=security_constructs,
    )
