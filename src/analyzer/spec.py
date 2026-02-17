import re
from pathlib import Path


_HEADER_RE = re.compile(r"^###\s+([A-Z]\d+)\.\s+(.+?)\s*$")


def load_metric_headers(path: Path) -> list[dict]:
    headers: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = _HEADER_RE.match(raw.strip())
        if not m:
            continue
        metric_id, title = m.group(1), m.group(2)
        headers.append({"id": metric_id, "title": title})
    # Also keep meta-level headings like M1.
    # (Already matched by regex.)
    return headers
