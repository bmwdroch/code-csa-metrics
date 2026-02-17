import resource
import time
from contextlib import contextmanager


class Timings:
    def __init__(self) -> None:
        self._starts: dict[str, float] = {}
        self._dur: dict[str, float] = {}
        self._t0 = time.perf_counter()

    @contextmanager
    def step(self, name: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            end = time.perf_counter()
            self._dur[f"{name}_sec"] = self._dur.get(f"{name}_sec", 0.0) + (end - start)

    def as_dict(self) -> dict[str, float]:
        total = time.perf_counter() - self._t0
        out = dict(self._dur)
        out["total_wall_sec"] = total
        return out

    def resource_snapshot(self) -> dict:
        # ru_maxrss is KB on Linux.
        ru = resource.getrusage(resource.RUSAGE_SELF)
        return {
            "ru_utime_sec": ru.ru_utime,
            "ru_stime_sec": ru.ru_stime,
            "ru_maxrss_kb": ru.ru_maxrss,
        }

