"""Генератор интерактивного HTML-отчёта CSQA.

Читает ``combined.json`` и создаёт самодостаточный HTML-файл с панелью сводных
показателей в HUD-стилистике и таблицей дефектов.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Разбор аргументов командной строки.

    Args:
        argv: Список аргументов. ``None`` означает ``sys.argv[1:]``.

    Returns:
        Пространство имён с полями ``input`` и ``output``.
    """
    parser = argparse.ArgumentParser(
        description="Генерация интерактивного HTML-отчёта CSQA",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Путь к combined.json",
    )
    parser.add_argument(
        "--output", "-o",
        default="csqa-report.html",
        help="Путь к выходному HTML-файлу (по умолчанию: csqa-report.html)",
    )
    parser.add_argument(
        "--max-graph-nodes",
        type=int,
        default=500,
        help="Максимум узлов для графа (по умолчанию: 500). "
             "При превышении отбираются наиболее значимые узлы.",
    )
    return parser.parse_args(argv)


def _load_combined(path: Path) -> dict[str, Any]:
    """Загрузка и валидация combined.json.

    Args:
        path: Путь к файлу.

    Returns:
        Десериализованный словарь.

    Raises:
        FileNotFoundError: Файл не найден.
        json.JSONDecodeError: Невалидный JSON.
    """
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


_TEST_CLASS_RE = re.compile(r"(^Test[A-Z]|Tests?$)")


def _is_test_node(method_id: str) -> bool:
    """Определяет, является ли метод тестовым по имени класса.

    Распознаёт стандартные соглашения именования Java-тестов:
    суффиксы ``Test``/``Tests`` и префикс ``Test`` перед заглавной буквой.

    Args:
        method_id: Полный идентификатор метода вида ``pkg.ClassName#method()``.

    Returns:
        ``True`` если метод принадлежит тестовому классу.
    """
    if "#" not in method_id:
        return False
    class_part = method_id.split("#")[0]
    class_name = class_part.rsplit(".", 1)[-1] if "." in class_part else class_part
    return bool(_TEST_CLASS_RE.search(class_name))


def _make_label(method_id: str) -> str:
    """Формирует короткую метку из полного идентификатора метода.

    Из ``org.springframework.samples.petclinic.owner.OwnerController#showOwner(int)``
    получится ``OwnerController#showOwner()``.

    Args:
        method_id: Полный идентификатор метода.

    Returns:
        Сокращённая метка ``ClassName#methodName()``.
    """
    if "#" not in method_id:
        parts = method_id.rsplit(".", 1)
        return parts[-1] if len(parts) > 1 else method_id

    class_part, method_part = method_id.split("#", 1)
    class_name = class_part.rsplit(".", 1)[-1] if "." in class_part else class_part
    method_name = method_part.split("(")[0] + "()"
    return f"{class_name}#{method_name}"


def _classify_nodes(
    all_nodes: list[str],
    entrypoint_ids: set[str],
    sink_ids: set[str],
) -> list[dict[str, Any]]:
    """Классификация узлов графа по типам.

    Каждый узел получает тип: ``entrypoint``, ``sink``, ``test`` или ``regular``.
    Приоритет: entrypoint > sink > test > regular.

    Args:
        all_nodes: Список всех идентификаторов методов.
        entrypoint_ids: Множество идентификаторов точек входа.
        sink_ids: Множество идентификаторов стоков.

    Returns:
        Список словарей с ключами ``id``, ``label``, ``type``.
    """
    result: list[dict[str, Any]] = []
    for node_id in all_nodes:
        if node_id in entrypoint_ids:
            node_type = "entrypoint"
        elif node_id in sink_ids:
            node_type = "sink"
        elif _is_test_node(node_id):
            node_type = "test"
        else:
            node_type = "regular"
        result.append({
            "id": node_id,
            "label": _make_label(node_id),
            "type": node_type,
        })
    return result


_METRIC_META: dict[str, dict[str, str]] = {
    "A1": {
        "name": "ASE", "title": "Открытость поверхности атаки",
        "group": "A", "score_key": "ASE",
        "hint": "Доля точек входа без аутентификации или валидации",
        "detail": "Считает, какая часть HTTP-эндпоинтов и публичных методов "
                  "не защищена аутентификацией или входной валидацией. "
                  "Чем выше значение, тем больше незащищённых входов в систему. "
                  "На узле показывается оценка конкретной точки входа: учитываются "
                  "наличие аннотаций безопасности, фильтров и проверок параметров.",
    },
    "A2": {
        "name": "ECI", "title": "Индекс взрывной сложности",
        "group": "A", "score_key": "ECI_avg",
        "hint": "Цикломатическая сложность методов, достижимых из точек входа",
        "detail": "Оценивает цикломатическую сложность методов, вызываемых из точек входа, "
                  "с учётом расстояния в графе вызовов. Сложный код, доступный "
                  "извне, — основной источник уязвимостей. На узле показывается "
                  "ECI конкретного метода: произведение его сложности на близость к входу.",
    },
    "A3": {
        "name": "IET", "title": "Входная энтропия",
        "group": "A", "score_key": "IET_system",
        "hint": "Разнообразие типов и протоколов точек входа",
        "detail": "Измеряет энтропию (разнообразие) типов точек входа: HTTP, gRPC, "
                  "очереди, CLI и т.д. Высокая энтропия означает больше протоколов, "
                  "каждый со своей моделью угроз. На узле — энтропия конкретной "
                  "точки входа, взвешенная по её типу.",
    },
    "B1": {
        "name": "IDS", "title": "Глубина эшелонированной защиты",
        "group": "B", "score_key": "IDS",
        "hint": "Есть ли несколько уровней проверок на пути к данным",
        "detail": "Проверяет, сколько независимых уровней защиты (аутентификация, "
                  "авторизация, валидация, санитизация) встречается на пути от входа "
                  "до приёмника. Низкое значение — хорошо: защита глубокая. "
                  "Высокое — один уровень или его отсутствие.",
    },
    "B2": {
        "name": "PPI", "title": "Индекс близости к привилегиям",
        "group": "B", "score_key": "PPI",
        "hint": "Насколько легко добраться от входа до привилегированного кода",
        "detail": "Измеряет минимальное расстояние в графе вызовов от публичного "
                  "эндпоинта до привилегированных операций (запись в БД, отправка "
                  "команд, управление пользователями). Чем ближе — тем выше риск. "
                  "Высокое значение означает, что привилегированный код легко достижим.",
    },
    "B3": {
        "name": "MPSP", "title": "Паритет защиты по путям",
        "group": "B", "score_key": "MPSP",
        "hint": "Равномерность защиты по всем путям выполнения",
        "detail": "Сравнивает уровень защиты на разных путях выполнения от входа "
                  "до приёмника. Если один путь защищён, а другой нет — это обход. "
                  "Низкое значение — все пути защищены одинаково. "
                  "Высокое — есть слабо защищённые обходные маршруты.",
    },
    "B4": {
        "name": "FSS", "title": "Оценка безопасного отказа",
        "group": "B", "score_key": "FSS",
        "hint": "Как ведёт себя система при ошибке: безопасно или нет",
        "detail": "Анализирует обработку исключений и ошибок: блокирует ли система "
                  "доступ при сбое (fail-secure) или открывает (fail-open). "
                  "Проверяет наличие catch-блоков на критических путях и поведение "
                  "при таймаутах. Низкое — безопасный отказ, высокое — рискованный.",
    },
    "C1": {
        "name": "TPC", "title": "Сложность пути заражённых данных",
        "group": "C", "score_key": "TPC",
        "hint": "Длина и разветвлённость путей от входа до потребителей",
        "detail": "Оценивает длину и число ветвлений на пути пользовательских "
                  "данных от точки входа до приёмника (БД, API, файл). Длинные "
                  "и ветвистые пути сложнее контролировать. Также учитывается "
                  "число последовательных переходов без санитизации.",
    },
    "C2": {
        "name": "ETI", "title": "Индекс прозрачности ошибок",
        "group": "C", "score_key": "ETI",
        "hint": "Утекает ли внутренняя информация в сообщениях об ошибках",
        "detail": "Проверяет, раскрывают ли обработчики ошибок внутреннюю структуру "
                  "системы: стектрейсы, имена таблиц, пути файлов, версии библиотек. "
                  "Такая информация помогает атакующему. "
                  "Низкое — ошибки скрыты, высокое — утечка деталей.",
    },
    "C3": {
        "name": "SFA", "title": "Анализ потоков секретов",
        "group": "C", "score_key": "SFA",
        "hint": "Проходят ли секреты (пароли, токены) через небезопасные пути",
        "detail": "Отслеживает потоки секретных данных (пароли, API-ключи, токены) "
                  "через граф вызовов. Проверяет, попадают ли они в логи, "
                  "ответы клиенту или незашифрованные хранилища. "
                  "Низкое — секреты изолированы, высокое — возможна утечка.",
    },
    "D1": {
        "name": "PAD", "title": "Дрейф атак на стыках технологий",
        "group": "D", "score_key": "PAD",
        "hint": "Риски на границах разных языков или фреймворков",
        "detail": "Оценивает риски при переходе данных между разными технологиями: "
                  "Java → SQL, Java → HTML, REST → gRPC. На каждой границе возможна "
                  "потеря контекста безопасности и новые классы атак (SQLi, XSS). "
                  "Низкое — однородный стек, высокое — много технологических границ.",
    },
    "D2": {
        "name": "TCPD", "title": "Глубина цепочки доверия",
        "group": "D", "score_key": "TCPD",
        "hint": "Сколько уровней посредников между входом и данными",
        "detail": "Подсчитывает число доверительных переходов: прокси, middleware, "
                  "сервисы, которые ретранслируют запрос без собственной проверки. "
                  "Каждый посредник — точка, где проверки могут быть пропущены. "
                  "Низкое — короткая цепочка, высокое — длинная с рисками.",
    },
    "E1": {
        "name": "OSDR", "title": "Риск зависимостей",
        "group": "E", "score_key": "OSDR",
        "hint": "Насколько рискован набор внешних зависимостей проекта",
        "detail": "Анализирует объявленные зависимости из pom.xml и build.gradle, "
                  "классифицирует их на базовые (Spring, Jackson, JUnit), внутренние "
                  "(самописные) и прочие. Штрафует за обилие сторонних библиотек "
                  "и самописную криптографию. "
                  "Низкое — минимум внешних рисков, высокое — широкая поверхность supply-chain.",
    },
    "F1": {
        "name": "VFCP", "title": "Предиктор сложности исправления",
        "group": "F", "score_key": "VFCP",
        "hint": "Насколько сложно будет исправить уязвимость в этом коде",
        "detail": "Оценивает, насколько трудоёмко исправление уязвимости: "
                  "связность кода, число зависимых модулей, глубина вложенности. "
                  "Сложный для исправления код остаётся уязвимым дольше. "
                  "Низкое — легко исправить, высокое — потребует масштабного рефакторинга.",
    },
    "F2": {
        "name": "SRP", "title": "Вероятность регрессии безопасности",
        "group": "F", "score_key": "SRP",
        "hint": "Риск того, что изменение кода сломает существующую защиту",
        "detail": "Измеряет, насколько вероятно, что изменение в одном месте "
                  "сломает защиту в другом: общие утилиты безопасности, "
                  "глобальные фильтры, разделяемые конфигурации. "
                  "Низкое — изолированная защита, высокое — хрупкие зависимости.",
    },
}

_GROUP_NAMES: dict[str, str] = {
    "A": "Поверхность атаки",
    "B": "Глубина защиты",
    "C": "Потоки данных",
    "D": "Технологические границы",
    "E": "Зависимости",
    "F": "Изменяемость",
}


def _trim_graph(
    all_nodes: list[str],
    all_edges: list[list[str]],
    entrypoint_ids: set[str],
    sink_ids: set[str],
    max_nodes: int,
) -> tuple[list[str], list[list[str]]]:
    """Сокращение графа до max_nodes наиболее значимых узлов.

    Приоритет отбора: точки входа, стоки, затем узлы с наибольшим числом
    связей. Рёбра фильтруются до оставшихся узлов.

    Args:
        all_nodes: Все идентификаторы узлов.
        all_edges: Все рёбра ``[source, target]``.
        entrypoint_ids: Множество точек входа.
        sink_ids: Множество стоков.
        max_nodes: Максимальное число узлов.

    Returns:
        Кортеж ``(trimmed_nodes, trimmed_edges)``.
    """
    if len(all_nodes) <= max_nodes:
        return all_nodes, all_edges

    # Считаем степень каждого узла
    degree: dict[str, int] = {}
    for src, tgt in all_edges:
        degree[src] = degree.get(src, 0) + 1
        degree[tgt] = degree.get(tgt, 0) + 1

    node_set = set(all_nodes)
    kept: set[str] = set()

    # 1. Все точки входа и стоки
    kept |= entrypoint_ids & node_set
    kept |= sink_ids & node_set

    # 2. Добираем по степени до лимита
    if len(kept) < max_nodes:
        remaining = [n for n in all_nodes if n not in kept]
        remaining.sort(key=lambda n: degree.get(n, 0), reverse=True)
        kept.update(remaining[: max_nodes - len(kept)])

    trimmed_nodes = [n for n in all_nodes if n in kept]
    trimmed_edges = [e for e in all_edges if e[0] in kept and e[1] in kept]
    return trimmed_nodes, trimmed_edges


def _build_graph_data(data: dict[str, Any], *, max_graph_nodes: int = 500) -> dict[str, Any]:
    """Формирование структуры GRAPH_DATA для встраивания в HTML.

    Args:
        data: Полный словарь combined.json.
        max_graph_nodes: Максимальное число узлов для графа визуализации.

    Returns:
        Словарь GRAPH_DATA со всеми полями для визуализации.
    """
    analyzer_obj = data.get("analyzer", data)
    analyzer = analyzer_obj if isinstance(analyzer_obj, dict) else {}
    meta_obj = analyzer.get("meta", {})
    metrics_obj = analyzer.get("metrics", {})
    meta = meta_obj if isinstance(meta_obj, dict) else {}
    metrics = metrics_obj if isinstance(metrics_obj, dict) else {}

    m1 = metrics.get("M1", {})
    a1 = metrics.get("A1", {})
    aggregate_obj = metrics.get("aggregate", {})
    aggregate = aggregate_obj if isinstance(aggregate_obj, dict) else {}
    aggregate_score_raw = aggregate.get("score")
    aggregate_score = round(float(aggregate_score_raw), 4) if isinstance(aggregate_score_raw, (int, float)) else None

    export = m1.get("export", {})
    raw_nodes = export.get("nodes", [])
    raw_edges = export.get("edges", [])

    # Определение точек входа: предпочитаем entrypoint_ids из export,
    # при отсутствии используем A1.sample[].method как запасной вариант
    if "entrypoint_ids" in export:
        entrypoint_ids = set(export["entrypoint_ids"])
    else:
        entrypoint_ids = {s["method"] for s in a1.get("sample", []) if "method" in s}

    sink_ids = set(export.get("sink_ids", []))

    # Если M1 сообщает о наличии стоков, но не экспортирует их ID,
    # определяем стоки эвристически: узлы с входящими и без исходящих рёбер,
    # не являющиеся точками входа и тестами.
    if not sink_ids and m1.get("sinks", 0) > 0:
        outgoing = set()
        incoming = set()
        for src, tgt in raw_edges:
            outgoing.add(src)
            incoming.add(tgt)
        test_pattern = re.compile(r'(?i)(test|spec|mock|stub)')
        for n in raw_nodes:
            if n in incoming and n not in outgoing and n not in entrypoint_ids:
                if not test_pattern.search(n):
                    sink_ids.add(n)

    # Сокращение графа до лимита
    all_nodes, all_edges = _trim_graph(
        raw_nodes, raw_edges, entrypoint_ids, sink_ids, max_graph_nodes,
    )
    visible_nodes = set(all_nodes)
    visible_entrypoint_ids = entrypoint_ids & visible_nodes
    visible_sink_ids = sink_ids & visible_nodes

    # Классификация узлов
    nodes = _classify_nodes(all_nodes, visible_entrypoint_ids, visible_sink_ids)

    # Рёбра
    edges = [{"source": e[0], "target": e[1]} for e in all_edges]

    # Детали точек входа из A1
    entrypoint_details: dict[str, dict[str, Any]] = {}
    for sample in a1.get("sample", []):
        mid = sample.get("method", "")
        if mid:
            entrypoint_details[mid] = {
                "has_auth": sample.get("has_auth", False),
                "has_validation": sample.get("has_validation", False),
                "score": sample.get("score", 0.0),
            }

    # Все метрики: нормализованные значения из _METRIC_META
    all_metrics: dict[str, Any] = {}
    for mid, meta_info in _METRIC_META.items():
        block = metrics.get(mid, {})
        score_key = meta_info["score_key"]
        value = block.get(score_key)
        all_metrics[mid] = {
            "id": mid,
            "name": meta_info["name"],
            "title": meta_info["title"],
            "hint": meta_info.get("hint", ""),
            "detail": meta_info.get("detail", ""),
            "group": meta_info["group"],
            "status": block.get("status", "not_available"),
            "value": round(value, 4) if value is not None else None,
        }

    # Оверлеи: данные по узлам для метрик A1, A2, A3
    metric_overlays: dict[str, dict[str, float]] = {}

    # A1: score per entrypoint
    a1_overlay: dict[str, float] = {}
    for sample in a1.get("sample", []):
        mid_s = sample.get("method", "")
        if mid_s and sample.get("score") is not None:
            a1_overlay[mid_s] = sample["score"]
    if a1_overlay:
        metric_overlays["A1"] = a1_overlay

    # A2: ECI per method
    a2 = metrics.get("A2", {})
    a2_overlay: dict[str, float] = {}
    for entry in a2.get("top", []):
        mid_e = entry.get("method", "")
        if mid_e and entry.get("ECI_norm") is not None:
            a2_overlay[mid_e] = entry["ECI_norm"]
    if a2_overlay:
        metric_overlays["A2"] = a2_overlay

    # A3: entropy per entrypoint
    a3 = metrics.get("A3", {})
    a3_overlay: dict[str, float] = {}
    for sample in a3.get("sample", []):
        mid_s = sample.get("method", "")
        if mid_s and sample.get("entropy") is not None:
            a3_overlay[mid_s] = sample["entropy"]
    if a3_overlay:
        metric_overlays["A3"] = a3_overlay

    # Сбор findings из всех метрик
    all_findings: list[dict[str, Any]] = []
    for mid in _METRIC_META:
        block = metrics.get(mid, {})
        for f in block.get("findings", []):
            all_findings.append(f)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 3))

    # Радар: средние значения по группам метрик
    group_values: dict[str, list[float]] = {}
    for mid, info in all_metrics.items():
        if info["value"] is not None and info["status"] == "ok":
            group_values.setdefault(info["group"], []).append(info["value"])

    radar_data: list[dict[str, Any]] = []
    for gid in ("A", "B", "C", "D", "E", "F"):
        vals = group_values.get(gid, [])
        avg = round(min(1.0, max(0.0, sum(vals) / len(vals))), 4) if vals else None
        radar_data.append({"group": gid, "label": _GROUP_NAMES[gid], "value": avg})

    repo_url = meta.get("repo_url", "")
    repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1] if repo_url else "unknown"

    return {
        "meta": {
            "repo_url": repo_url,
            "repo_name": repo_name,
            "mode": meta.get("mode", ""),
            "git_head": meta.get("git_head", ""),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        "summary": {
            "nodes": len(all_nodes),
            "edges": len(all_edges),
            "entrypoints": len(visible_entrypoint_ids),
            "sinks": len(visible_sink_ids),
            "aggregate_score": aggregate_score,
        },
        "nodes": nodes,
        "edges": edges,
        "entrypoint_details": entrypoint_details,
        "all_metrics": all_metrics,
        "metric_overlays": metric_overlays,
        "radar": radar_data,
        "findings": all_findings,
        "aggregate": {
            "score": aggregate_score,
            "components": aggregate.get("components", {}),
        },
    }


def _render_html(graph_data: dict[str, Any]) -> str:
    """Генерация полного HTML-документа с встроенными CSS, JS и данными графа.

    Создаёт самодостаточный HTML с двумя вкладками: дашборд (радар + карточки
    метрик) и граф (D3 force-directed с оверлеями метрик). Все стили и скрипты
    встроены. Тема оформления — HUD dark.

    Args:
        graph_data: Структура GRAPH_DATA, сформированная ``_build_graph_data``.

    Returns:
        Строка с полным HTML-документом.
    """
    data_json = json.dumps(graph_data, ensure_ascii=False, indent=2)
    # Предотвращение выхода из контекста <script> через последовательность </
    data_json = data_json.replace("</", "<\\/")
    meta = graph_data["meta"]
    summary = graph_data["summary"]
    score_val = summary.get("aggregate_score")
    has_aggregate_score = isinstance(score_val, (int, float))
    score_pct = round(score_val * 100, 1) if has_aggregate_score else 0.0
    commit_short = meta["git_head"][:8] if meta["git_head"] else "n/a"

    if not has_aggregate_score:
        score_color = "#94a3b8"  # gray — unavailable
        score_label = "нет данных"
        score_display = "N/A"
    elif score_val < 0.3:
        score_color = "#34d399"  # green — good
        score_label = "низкий риск"
        score_display = f"{score_pct}<span style=\"font-size:0.875rem;font-weight:400;color:var(--text-tertiary)\">%</span>"
    elif score_val < 0.6:
        score_color = "#fbbf24"  # yellow — moderate
        score_label = "средний риск"
        score_display = f"{score_pct}<span style=\"font-size:0.875rem;font-weight:400;color:var(--text-tertiary)\">%</span>"
    else:
        score_color = "#f87171"  # red — high
        score_label = "высокий риск"
        score_display = f"{score_pct}<span style=\"font-size:0.875rem;font-weight:400;color:var(--text-tertiary)\">%</span>"

    html = f"""\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CSQA Report &mdash; {_escape_html(meta["repo_name"])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ======================================================================
   CSS Variables (HUD Theme)
   ====================================================================== */
:root {{
  --bg: #000000;
  --surface-1: #0d0d0d;
  --surface-2: #171717;
  --surface-3: #1f1f1f;
  --border: rgba(255, 255, 255, 0.1);
  --border-strong: rgba(255, 255, 255, 0.18);
  --text-primary: #ffffff;
  --text-secondary: #a3a3a3;
  --text-tertiary: #6b6b6b;
  --accent: #fb923c;
  --accent-soft: rgba(249, 115, 22, 0.1);
  --danger: #f87171;
  --success: #34d399;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

html, body {{
  font-family: 'JetBrains Mono', monospace;
  background: var(--bg);
  color: var(--text-primary);
  height: 100%;
  overflow: hidden;
}}

/* ======================================================================
   Layout
   ====================================================================== */
#app {{
  display: flex;
  flex-direction: column;
  height: 100vh;
}}

/* ======================================================================
   Header / HUD Panel
   ====================================================================== */
.hud-panel {{
  position: relative;
  background: rgba(13, 13, 13, 0.85);
  backdrop-filter: blur(15px);
  -webkit-backdrop-filter: blur(15px);
  border: 1px solid var(--border);
  padding: 0.75rem 1.25rem;
}}
.hud-panel-header {{
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: nowrap;
  min-width: 0;
}}
.hud-panel-title {{
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}}
.hud-panel-meta {{
  display: flex;
  gap: 1rem;
  align-items: center;
  flex-wrap: nowrap;
  margin-left: auto;
  flex-shrink: 1;
  min-width: 0;
  overflow: hidden;
}}
.hud-panel-meta span {{
  font-size: 0.6875rem;
  color: var(--text-tertiary);
  letter-spacing: 0.05em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  flex-shrink: 1;
  min-width: 0;
}}
.hud-panel-meta span b {{
  color: var(--text-secondary);
  font-weight: 500;
}}
.hud-panel-meta .meta-secondary {{
  flex-shrink: 2;
}}

/* ======================================================================
   Dot Corners
   ====================================================================== */
.dot-corner {{
  position: absolute;
  width: 3px;
  height: 3px;
  background: rgba(255, 255, 255, 0.15);
  z-index: 2;
}}
.dot-corner.tl {{ top: 6px; left: 6px; }}
.dot-corner.tr {{ top: 6px; right: 6px; }}
.dot-corner.bl {{ bottom: 6px; left: 6px; }}
.dot-corner.br {{ bottom: 6px; right: 6px; }}

/* ======================================================================
   Hud Panel Tabs (moved into header)
   ====================================================================== */
.hud-panel-tabs {{
  display: flex;
  gap: 0.375rem;
  flex-shrink: 0;
}}

/* ======================================================================
   Summary Stats (next to radar)
   ====================================================================== */
.summary-stats {{
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
  min-width: 160px;
}}
.summary-stat-label {{
  font-size: 0.5625rem;
  font-weight: 500;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.12em;
  margin-bottom: 0.15rem;
}}
.summary-stat-value {{
  font-size: 1.25rem;
  font-weight: 700;
  line-height: 1;
}}
.summary-stat-sub {{
  font-size: 0.5625rem;
  margin-top: 0.2rem;
}}
.summary-score-bar {{
  height: 3px;
  background: var(--surface-2);
  margin-top: 0.25rem;
  overflow: hidden;
  width: 100%;
}}
.summary-score-fill {{
  height: 100%;
  transition: width 0.3s ease;
}}

/* ======================================================================
   Tab Content
   ====================================================================== */
.tab-content {{
  display: none;
  flex: 1;
  min-height: 0;
}}
.tab-content.active[data-tab-type="dashboard"] {{
  display: block;
  overflow-y: auto;
}}
.tab-content.active[data-tab-type="graph"] {{
  display: flex;
  flex-direction: column;
}}
.tab-content.active[data-tab-type="findings"] {{
  display: block;
  overflow-y: auto;
}}

/* ======================================================================
   Dashboard Content
   ====================================================================== */
.dashboard-content {{
  padding: 2rem 2.5rem;
  overflow-y: auto;
  flex: 1;
}}

/* Radar + Stats */
.radar-container {{
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 2.5rem;
  padding: 1rem 0 1.5rem;
}}

/* Metric Cards Grid */
.metrics-grid {{
  max-width: 1100px;
  margin: 0 auto;
}}
.metrics-group {{
  margin-bottom: 1.5rem;
}}
.metrics-group-header {{
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.75rem;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--border);
}}
.metrics-group-row {{
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}}
.metric-card {{
  position: relative;
  flex: 1 1 200px;
  max-width: 260px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  padding: 1rem 1.125rem;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
}}
.metric-card:hover {{
  border-color: var(--border-strong);
  background: var(--surface-3);
}}
.metric-card.disabled {{
  opacity: 0.35;
  cursor: default;
  pointer-events: none;
}}
.metric-card-id {{
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.25rem;
}}
.metric-card-name {{
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 0.125rem;
}}
.metric-card-title {{
  font-size: 0.75rem;
  color: var(--text-tertiary);
  margin-bottom: 0.5rem;
  line-height: 1.3;
}}
.metric-card-hint {{
  font-size: 0.6875rem;
  color: var(--text-tertiary);
  line-height: 1.35;
  margin-bottom: 0.5rem;
  opacity: 0.7;
}}
.detail-metric-info {{
  background: var(--surface-2);
  border: 1px solid var(--border);
  padding: 0.75rem;
  margin-bottom: 1rem;
}}
.detail-metric-header {{
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  margin-bottom: 0.35rem;
}}
.detail-metric-id {{
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--accent);
}}
.detail-metric-name {{
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-primary);
}}
.detail-metric-desc {{
  font-size: 0.6875rem;
  color: var(--text-tertiary);
  line-height: 1.45;
  margin-top: 0.25rem;
}}
.metric-card-value {{
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.35rem;
}}
.metric-progress {{
  width: 100%;
  height: 3px;
  background: var(--surface-1);
  overflow: hidden;
}}
.metric-progress-fill {{
  height: 100%;
  transition: width 0.3s ease;
}}

/* ======================================================================
   Btn-clipped (shared)
   ====================================================================== */
.btn-clipped {{
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0.4rem 0.8rem;
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.6875rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  cursor: pointer;
  transition: all 0.2s ease;
  z-index: 0;
  --btn-cut: 6px;
  --btn-border-color: var(--border);
  --btn-fill: var(--bg);
  clip-path: polygon(
    0 0,
    calc(100% - var(--btn-cut)) 0,
    100% var(--btn-cut),
    100% 100%,
    var(--btn-cut) 100%,
    0 calc(100% - var(--btn-cut))
  );
}}
.btn-clipped::before,
.btn-clipped::after {{
  content: '';
  position: absolute;
  inset: 0;
  pointer-events: none;
}}
.btn-clipped::before {{
  background: var(--btn-border-color);
  z-index: -2;
}}
.btn-clipped::after {{
  inset: 1px;
  background: var(--btn-fill);
  clip-path: polygon(
    0 0,
    calc(100% - var(--btn-cut)) 0,
    100% var(--btn-cut),
    100% 100%,
    var(--btn-cut) 100%,
    0 calc(100% - var(--btn-cut))
  );
  z-index: -1;
  transition: background-color 0.2s ease;
}}
.btn-clipped:hover {{
  color: var(--text-primary);
  --btn-border-color: var(--border-strong);
  --btn-fill: var(--surface-2);
}}
.btn-clipped.active {{
  color: var(--bg);
  --btn-border-color: var(--accent);
  --btn-fill: var(--accent);
  font-weight: 600;
}}

/* ======================================================================
   Toolbar (Filter Buttons inside Graph tab)
   ====================================================================== */
.toolbar {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--surface-1);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  flex-wrap: wrap;
}}
.toolbar-label {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-right: 0.5rem;
}}
.toolbar-separator {{
  width: 1px;
  height: 20px;
  background: var(--border);
  margin: 0 0.25rem;
}}
.metric-select {{
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.6875rem;
  padding: 0.35rem 0.5rem;
  outline: none;
  cursor: pointer;
  transition: border-color 0.2s;
}}
.metric-select:hover, .metric-select:focus {{
  border-color: var(--border-strong);
  color: var(--text-primary);
}}
.overlay-info {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  margin-left: 0.35rem;
}}

/* ======================================================================
   Findings Container
   ====================================================================== */
.findings-wrapper {{
  flex: 1;
  overflow-y: auto;
  padding: 1rem 1.5rem;
}}
.findings-toolbar {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border-bottom: 1px solid var(--border);
  flex-wrap: wrap;
}}
.findings-count {{
  font-size: 0.75rem;
  color: var(--text-tertiary);
  margin-left: auto;
}}
.finding-card {{
  border: 1px solid var(--border);
  background: var(--surface-1);
  padding: 0.875rem 1rem;
  margin-bottom: 0.5rem;
  transition: border-color 0.15s;
}}
.finding-card:hover {{
  border-color: var(--border-strong);
}}
.finding-header {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}}
.finding-metric {{
  font-size: 0.6875rem;
  font-weight: 700;
  padding: 0.15rem 0.4rem;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  letter-spacing: 0.05em;
}}
.finding-severity {{
  font-size: 0.5625rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 0.15rem 0.4rem;
  border: 1px solid;
}}
.finding-severity.critical {{ color: #f87171; border-color: rgba(248,113,113,0.4); background: rgba(248,113,113,0.1); }}
.finding-severity.high {{ color: #fb923c; border-color: rgba(251,146,60,0.4); background: rgba(251,146,60,0.1); }}
.finding-severity.medium {{ color: #fbbf24; border-color: rgba(251,191,36,0.4); background: rgba(251,191,36,0.1); }}
.finding-severity.low {{ color: #34d399; border-color: rgba(52,211,153,0.4); background: rgba(52,211,153,0.1); }}
.finding-location {{
  font-size: 0.6875rem;
  color: var(--text-tertiary);
  margin-left: auto;
  font-family: 'JetBrains Mono', 'SF Mono', monospace;
}}
.finding-what {{
  font-size: 0.8125rem;
  color: var(--text-primary);
  margin-bottom: 0.375rem;
  line-height: 1.4;
}}
.finding-detail {{
  font-size: 0.6875rem;
  color: var(--text-secondary);
  line-height: 1.5;
}}
.finding-detail strong {{
  color: var(--text-tertiary);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.5625rem;
  letter-spacing: 0.05em;
}}
.no-findings {{
  text-align: center;
  padding: 3rem;
  color: var(--text-tertiary);
  font-size: 0.875rem;
}}

/* ======================================================================
   File Groups (findings tab)
   ====================================================================== */
.file-group {{
  margin-bottom: 0.75rem;
  border: 1px solid var(--border);
}}
.file-group-header {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: var(--surface-2);
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}}
.file-group-header:hover {{
  background: var(--surface-3);
}}
.file-group-name {{
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--text-secondary);
  font-family: 'JetBrains Mono', monospace;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.file-group-count {{
  font-size: 0.5625rem;
  font-weight: 600;
  padding: 0.1rem 0.4rem;
  background: var(--surface-1);
  border: 1px solid var(--border);
  color: var(--text-tertiary);
  flex-shrink: 0;
}}
.file-group-arrow {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  flex-shrink: 0;
  transition: transform 0.15s;
}}
.file-group-body {{
  border-top: 1px solid var(--border);
}}
.file-group-body.collapsed {{
  display: none;
}}
.finding-row {{
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  cursor: pointer;
  transition: background 0.1s;
  border-bottom: 1px solid transparent;
}}
.finding-row:hover {{
  background: var(--surface-2);
}}
.finding-row:last-child {{
  border-bottom: none;
}}
.finding-row-dot {{
  font-size: 0.5rem;
  flex-shrink: 0;
  margin-top: 0.15rem;
}}
.finding-row-what {{
  font-size: 0.75rem;
  color: var(--text-primary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.finding-row-line {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  font-family: 'JetBrains Mono', monospace;
  flex-shrink: 0;
}}
.finding-row-detail {{
  padding: 0.5rem 0.75rem 0.625rem 2rem;
  background: var(--surface-1);
  border-top: 1px solid var(--border);
  font-size: 0.6875rem;
  color: var(--text-secondary);
  line-height: 1.5;
}}
.finding-row-detail.collapsed {{
  display: none;
}}
.finding-row-detail strong {{
  color: var(--text-tertiary);
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.5625rem;
  letter-spacing: 0.05em;
}}
.finding-row-method {{
  font-size: 0.625rem;
  color: var(--text-tertiary);
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 0.35rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}

/* Badges */
.badge {{
  display: inline-flex;
  align-items: center;
  padding: 0.2rem 0.5rem;
  font-size: 0.5625rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  margin-right: 0.35rem;
  margin-bottom: 0.25rem;
}}
.badge.accent {{
  background: var(--accent-soft);
  border-color: rgba(249, 115, 22, 0.3);
  color: var(--accent);
}}
.badge.danger {{
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.3);
  color: #f87171;
}}
.badge.success {{
  background: rgba(16, 185, 129, 0.1);
  border-color: rgba(16, 185, 129, 0.3);
  color: #34d399;
}}
.badge.warning {{
  background: rgba(245, 158, 11, 0.1);
  border-color: rgba(245, 158, 11, 0.3);
  color: #fbbf24;
}}


/* ======================================================================
   Download Button
   ====================================================================== */
.btn-back {{
  background: none;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 0.6875rem;
  font-family: inherit;
  padding: 0.25rem 0.6rem;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s, background 0.15s;
  margin-left: 0.5rem;
}}
.btn-back:hover {{
  color: var(--text-primary);
  border-color: var(--border-strong);
  background: var(--surface-3);
}}
.btn-download {{
  background: none;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 0.6875rem;
  font-family: inherit;
  padding: 0.25rem 0.6rem;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s, background 0.15s;
  margin-left: 0.5rem;
}}
.btn-download:hover {{
  color: var(--accent);
  border-color: var(--accent);
  background: var(--accent-soft);
}}

/* ======================================================================
   Custom Scrollbar
   ====================================================================== */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--surface-1); }}
::-webkit-scrollbar-thumb {{ background: rgba(249, 115, 22, 0.35); }}
::-webkit-scrollbar-thumb:hover {{ background: rgba(249, 115, 22, 0.65); }}
* {{ scrollbar-width: thin; scrollbar-color: rgba(249,115,22,0.35) var(--surface-1); }}
</style>
</head>
<body>
<div id="app">

  <!-- Header -->
  <div class="hud-panel">
    <span class="dot-corner tl"></span>
    <span class="dot-corner tr"></span>
    <span class="dot-corner bl"></span>
    <span class="dot-corner br"></span>
    <div class="hud-panel-header">
      <div class="hud-panel-title">CSQA &middot; ОЦЕНКА КАЧЕСТВА И БЕЗОПАСНОСТИ КОДА</div>
      <div class="hud-panel-tabs">
        <button class="btn-clipped active" data-tab="dashboard" onclick="switchTab('dashboard')">Дашборд</button>
        <button class="btn-clipped" data-tab="findings" onclick="switchTab('findings')">Дефекты</button>
      </div>
      <div class="hud-panel-meta">
        <span>репозиторий: <b>{_escape_html(meta["repo_name"])}</b></span>
        # <span class="meta-secondary">mode: <b>{_escape_html(meta["mode"])}</b></span>
        <span class="meta-secondary">коммит: <b>{_escape_html(commit_short)}</b></span>
        <span class="meta-secondary">дата: <b>{_escape_html(meta["generated_at"])}</b></span>
        <button class="btn-back" id="btn-back" onclick="goHome()" style="display:none"
                title="Вернуться к выбору репозитория">&#8592; Новый анализ</button>
        <button class="btn-download" id="btn-download" onclick="downloadReport()" style="display:none"
                title="Скачать отчёт как HTML-файл">&#8681; Скачать</button>
      </div>
    </div>
  </div>

  <!-- ================================================================
       Dashboard Tab
       ================================================================ -->
  <div id="tab-dashboard" class="tab-content active" data-tab-type="dashboard">
    <div class="dashboard-content">
      <div class="radar-container">
        <svg id="radar-svg" width="420" height="420"></svg>
        <div class="summary-stats">
          <div>
            <div class="summary-stat-label" title="HTTP-эндпоинты и другие публичные методы, доступные извне">Точки входа</div>
            <div class="summary-stat-value" style="color:var(--accent)">{summary["entrypoints"]}</div>
          </div>
          <div>
            <div class="summary-stat-label" title="Приёмники данных — методы, записывающие данные: БД, API, файлы и т.д.">Приёмники</div>
            <div class="summary-stat-value" style="color:var(--danger)">{summary["sinks"]}</div>
          </div>
          <div>
            <div class="summary-stat-label" title="Средневзвешенный уровень безопасности: 0% — максимальная защищённость, 100% — максимальный риск">Общая оценка</div>
            <div class="summary-stat-value" style="color:{score_color}">{score_pct}%</div>
            <div class="summary-stat-sub" style="color:{score_color}">{score_label}</div>
            <div class="summary-score-bar">
              <div class="summary-score-fill" style="width:{score_pct}%;background:{score_color}"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="metrics-grid" id="metrics-cards"></div>
    </div>
  </div>

  <!-- ================================================================
       Findings Tab
       ================================================================ -->
  <div id="tab-findings" class="tab-content" data-tab-type="findings">

    <!-- Toolbar -->
    <div class="findings-toolbar">
      <span class="toolbar-label">Группа:</span>
      <button class="btn-clipped active" data-group="all" onclick="setGroupFilter('all')">Все</button>
      <button class="btn-clipped" data-group="A" onclick="setGroupFilter('A')">A</button>
      <button class="btn-clipped" data-group="B" onclick="setGroupFilter('B')">B</button>
      <button class="btn-clipped" data-group="C" onclick="setGroupFilter('C')">C</button>
      <button class="btn-clipped" data-group="D" onclick="setGroupFilter('D')">D</button>
      <button class="btn-clipped" data-group="E" onclick="setGroupFilter('E')">E</button>
      <button class="btn-clipped" data-group="F" onclick="setGroupFilter('F')">F</button>

      <div class="toolbar-separator"></div>

      <span class="toolbar-label">Серьёзность:</span>
      <button class="btn-clipped active" data-sev="all" onclick="setSevFilter('all')">Все</button>
      <button class="btn-clipped" data-sev="critical" onclick="setSevFilter('critical')">Critical</button>
      <button class="btn-clipped" data-sev="high" onclick="setSevFilter('high')">High</button>
      <button class="btn-clipped" data-sev="medium" onclick="setSevFilter('medium')">Medium</button>
      <button class="btn-clipped" data-sev="low" onclick="setSevFilter('low')">Low</button>

      <span class="findings-count" id="findings-count"></span>
    </div>

    <!-- Findings List -->
    <div class="findings-wrapper" id="findings-list"></div>

  </div>

</div>

<script>
// =========================================================================
//  Data
// =========================================================================
const GRAPH_DATA = {data_json};

// =========================================================================
//  Constants
// =========================================================================
const GROUP_NAMES = {{
  A: 'Поверхность атаки',
  B: 'Глубина защиты',
  C: 'Потоки данных',
  D: 'Технологические границы',
  E: 'Зависимости',
  F: 'Изменяемость',
}};

// =========================================================================
//  State
// =========================================================================
let currentGroupFilter = 'all';
let currentSevFilter = 'all';

// =========================================================================
//  Helpers
// =========================================================================
function escapeHtml(str) {{
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}}

function riskColor(t) {{
  t = Math.max(0, Math.min(1, t));
  const r1 = 0x34, g1 = 0xd3, b1 = 0x99;  // #34d399 green
  const r2 = 0xfb, g2 = 0xbf, b2 = 0x24;  // #fbbf24 yellow
  const r3 = 0xf8, g3 = 0x71, b3 = 0x71;  // #f87171 red
  let r, g, b;
  if (t < 0.5) {{
    const s = t * 2;
    r = r1 + (r2 - r1) * s;
    g = g1 + (g2 - g1) * s;
    b = b1 + (b2 - b1) * s;
  }} else {{
    const s = (t - 0.5) * 2;
    r = r2 + (r3 - r2) * s;
    g = g2 + (g3 - g2) * s;
    b = b2 + (b3 - b2) * s;
  }}
  return `rgb(${{Math.round(r)}},${{Math.round(g)}},${{Math.round(b)}})`;
}}

function riskBarColor(v) {{
  if (v < 0.3) return '#34d399';
  if (v < 0.7) return '#fbbf24';
  return '#f87171';
}}

// =========================================================================
//  Tab Switching
// =========================================================================
function switchTab(tabId) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.hud-panel-tabs .btn-clipped').forEach(btn => btn.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  document.querySelector('.hud-panel-tabs .btn-clipped[data-tab="' + tabId + '"]').classList.add('active');
}}

// =========================================================================
//  Build Radar Chart (pure SVG, no D3)
// =========================================================================
(function buildRadar() {{
  const svgEl = document.getElementById('radar-svg');
  const W = 420, H = 420;
  const cx = W / 2, cy = H / 2;
  const R = 150;
  const data = GRAPH_DATA.radar;
  const n = data.length;
  const angleSlice = (2 * Math.PI) / n;
  const levels = [0.25, 0.5, 0.75, 1.0];
  const ns = 'http://www.w3.org/2000/svg';

  function svgCreate(tag, attrs) {{
    const el = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  }}

  const gRadar = svgCreate('g', {{ transform: `translate(${{cx}},${{cy}})` }});
  svgEl.appendChild(gRadar);

  levels.forEach(lv => {{
    const pts = [];
    for (let i = 0; i < n; i++) {{
      const angle = angleSlice * i - Math.PI / 2;
      pts.push(`${{R * lv * Math.cos(angle)}},${{R * lv * Math.sin(angle)}}`);
    }}
    gRadar.appendChild(svgCreate('polygon', {{
      points: pts.join(' '), fill: 'none',
      stroke: 'rgba(255,255,255,0.12)',
      'stroke-width': lv === 1.0 ? 1.5 : 0.5,
      'stroke-dasharray': lv === 1.0 ? 'none' : '2,3'
    }}));

    const la = angleSlice * 0 - Math.PI / 2;
    const txt = svgCreate('text', {{
      x: R * lv * Math.cos(la) + 6, y: R * lv * Math.sin(la) - 4,
      fill: 'rgba(255,255,255,0.25)', 'font-size': '9px',
      'font-family': 'JetBrains Mono, monospace'
    }});
    txt.textContent = Math.round(lv * 100) + '%';
    gRadar.appendChild(txt);
  }});

  data.forEach((d, i) => {{
    const angle = angleSlice * i - Math.PI / 2;
    gRadar.appendChild(svgCreate('line', {{
      x1: 0, y1: 0, x2: R * Math.cos(angle), y2: R * Math.sin(angle),
      stroke: 'rgba(255,255,255,0.1)', 'stroke-width': 1
    }}));
    const lx = (R + 18) * Math.cos(angle);
    const ly = (R + 18) * Math.sin(angle);
    const lbl = svgCreate('text', {{
      x: lx, y: ly, 'text-anchor': 'middle', 'dominant-baseline': 'central',
      fill: '#e5e5e5', 'font-size': '13px', 'font-weight': '700',
      'font-family': 'JetBrains Mono, monospace'
    }});
    lbl.textContent = d.group;
    gRadar.appendChild(lbl);

    const v = d.value != null ? d.value : null;
    if (v !== null) {{
      const vx = (R * v + 10) * Math.cos(angle);
      const vy = (R * v + 10) * Math.sin(angle);
      const vt = svgCreate('text', {{
        x: vx, y: vy, 'text-anchor': 'middle', 'dominant-baseline': 'central',
        fill: riskBarColor(v), 'font-size': '9px', 'font-weight': '600',
        'font-family': 'JetBrains Mono, monospace'
      }});
      vt.textContent = Math.round(v * 100) + '%';
      gRadar.appendChild(vt);
    }}
  }});

  const valuePts = data.map((d, i) => {{
    const v = d.value != null ? Math.min(1, Math.max(0, d.value)) : 0;
    const angle = angleSlice * i - Math.PI / 2;
    return `${{R * v * Math.cos(angle)}},${{R * v * Math.sin(angle)}}`;
  }});
  gRadar.appendChild(svgCreate('polygon', {{
    points: valuePts.join(' '), fill: 'rgba(251,146,60,0.12)',
    stroke: '#fb923c', 'stroke-width': 2
  }}));

  data.forEach((d, i) => {{
    if (d.value != null) {{
      const v = Math.min(1, Math.max(0, d.value));
      const angle = angleSlice * i - Math.PI / 2;
      gRadar.appendChild(svgCreate('circle', {{
        cx: R * v * Math.cos(angle), cy: R * v * Math.sin(angle),
        r: 4, fill: '#fb923c', stroke: '#000', 'stroke-width': 1.5
      }}));
    }}
  }});
}})();

// =========================================================================
//  Build Metric Cards
// =========================================================================
(function buildMetricCards() {{
  const container = document.getElementById('metrics-cards');
  const groups = {{}};
  Object.values(GRAPH_DATA.all_metrics).forEach(m => {{
    if (!groups[m.group]) groups[m.group] = [];
    groups[m.group].push(m);
  }});
  const groupOrder = ['A', 'B', 'C', 'D', 'E', 'F'];
  groupOrder.forEach(gid => {{
    const items = groups[gid];
    if (!items) return;
    const grp = document.createElement('div');
    grp.className = 'metrics-group';
    const hdr = document.createElement('div');
    hdr.className = 'metrics-group-header';
    hdr.textContent = gid + ' \u2014 ' + (GROUP_NAMES[gid] || gid);
    grp.appendChild(hdr);
    const row = document.createElement('div');
    row.className = 'metrics-group-row';
    items.forEach(m => {{
      const card = document.createElement('div');
      card.className = 'metric-card' + (m.status !== 'ok' ? ' disabled' : '');
      card.onclick = function() {{
        switchTab('findings');
        setGroupFilter(gid);
      }};
      const val = m.value !== null ? m.value : 0;
      const pct = Math.round(val * 100);
      card.innerHTML =
        '<div class="metric-card-id">' + escapeHtml(m.id) + '</div>' +
        '<div class="metric-card-name">' + escapeHtml(m.name) + '</div>' +
        '<div class="metric-card-title">' + escapeHtml(m.title) + '</div>' +
        '<div class="metric-card-hint">' + escapeHtml(m.hint || '') + '</div>' +
        '<div class="metric-card-value">' + (m.value !== null ? pct + '%' : 'N/A') + '</div>' +
        '<div class="metric-progress"><div class="metric-progress-fill" style="width:' +
        pct + '%;background:' + (m.value !== null ? riskBarColor(val) : '#333') + '"></div></div>';
      row.appendChild(card);
    }});
    grp.appendChild(row);
    container.appendChild(grp);
  }});
}})();

// =========================================================================
//  Build Findings List
// =========================================================================
function renderFindings() {{
  const list = document.getElementById('findings-list');
  const countEl = document.getElementById('findings-count');
  const findings = GRAPH_DATA.findings || [];

  const filtered = findings.filter(f => {{
    const group = (f.metric || '').charAt(0);
    if (currentGroupFilter !== 'all' && group !== currentGroupFilter) return false;
    if (currentSevFilter !== 'all' && f.severity !== currentSevFilter) return false;
    return true;
  }});

  countEl.textContent = filtered.length + ' / ' + findings.length;

  if (filtered.length === 0) {{
    list.innerHTML = '<div class="no-findings">Дефекты не обнаружены (или отфильтрованы)</div>';
    return;
  }}

  let html = '';
  filtered.forEach(f => {{
    const loc = f.file ? (f.file + (f.line ? ':' + f.line : '')) : '';
    html += '<div class="finding-card">' +
      '<div class="finding-header">' +
        '<span class="finding-metric">' + escapeHtml(f.metric || '') + '</span>' +
        '<span class="finding-severity ' + (f.severity || 'low') + '">' + escapeHtml(f.severity || 'low') + '</span>' +
        (f.method ? '<span style="font-size:0.6875rem;color:var(--text-secondary)">' + escapeHtml(f.method) + '</span>' : '') +
        (loc ? '<span class="finding-location">' + escapeHtml(loc) + '</span>' : '') +
      '</div>' +
      '<div class="finding-what">' + escapeHtml(f.what || '') + '</div>' +
      '<div class="finding-detail">' +
        '<strong>Почему: </strong>' + escapeHtml(f.why || '') + '<br>' +
        '<strong>Исправление: </strong>' + escapeHtml(f.fix || '') +
      '</div>' +
    '</div>';
  }});
  list.innerHTML = html;
}}

function setGroupFilter(group) {{
  currentGroupFilter = group;
  document.querySelectorAll('.findings-toolbar .btn-clipped[data-group]').forEach(btn => {{
    btn.classList.toggle('active', btn.dataset.group === group);
  }});
  renderFindings();
}}

function setSevFilter(sev) {{
  currentSevFilter = sev;
  document.querySelectorAll('.findings-toolbar .btn-clipped[data-sev]').forEach(btn => {{
    btn.classList.toggle('active', btn.dataset.sev === sev);
  }});
  renderFindings();
}}

renderFindings();

// =========================================================================
//  Download Report
// =========================================================================
function downloadReport() {{
  const blob = new Blob([document.documentElement.outerHTML], {{type: 'text/html;charset=utf-8'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'csqa-report-' + (GRAPH_DATA.meta.repo_name || 'report') + '.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}

// =========================================================================
//  Navigation — back to home (only when served over HTTP(S), not from file://)
// =========================================================================
function goHome() {{
  // /TOKEN/report/JOB_ID  ->  /TOKEN/
  const parts = window.location.pathname.split('/report/');
  window.location.href = parts[0] + '/';
}}

// Show action buttons only when served over HTTP(S)
if (window.location.protocol !== 'file:') {{
  const btnBack = document.getElementById('btn-back');
  if (btnBack) btnBack.style.display = '';
  const btnDownload = document.getElementById('btn-download');
  if (btnDownload) btnDownload.style.display = '';
}}
</script>
</body>
</html>"""

    return html


def _escape_html(text: str) -> str:
    """Экранирование спецсимволов HTML.

    Args:
        text: Исходная строка.

    Returns:
        Строка с заменёнными ``&``, ``<``, ``>``, ``"`` и ``'``.
    """
    return html.escape(text, quote=True)


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI-скрипта.

    Args:
        argv: Аргументы командной строки. ``None`` означает ``sys.argv[1:]``.

    Returns:
        Код возврата: 0 при успехе, 1 при ошибке.
    """
    args = _parse_args(argv)
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Ошибка: файл не найден: {input_path}", file=sys.stderr)
        return 1

    try:
        data = _load_combined(input_path)
    except json.JSONDecodeError as exc:
        print(f"Ошибка разбора JSON: {exc}", file=sys.stderr)
        return 1

    graph_data = _build_graph_data(data, max_graph_nodes=args.max_graph_nodes)
    html = _render_html(graph_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    node_counts = {}
    for n in graph_data["nodes"]:
        node_counts[n["type"]] = node_counts.get(n["type"], 0) + 1

    print(f"Отчёт CSQA сгенерирован: {output_path}")
    print(f"  Узлов: {len(graph_data['nodes'])} "
          f"(entrypoint={node_counts.get('entrypoint', 0)}, "
          f"sink={node_counts.get('sink', 0)}, "
          f"test={node_counts.get('test', 0)}, "
          f"regular={node_counts.get('regular', 0)})")
    print(f"  Связей: {len(graph_data['edges'])}")
    print(f"  Размер файла: {output_path.stat().st_size:,} байт")
    available = sum(1 for m in graph_data["all_metrics"].values() if m["status"] == "ok")
    total = len(graph_data["all_metrics"])
    print(f"  Метрик: {available}/{total} доступно")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
