"""IP별 요청 제한 (보안 DEV2). 메모리 기반이라 파드마다 따로 센다 (파드 N개면 최대 N배)."""
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    """키(IP)마다 최근 window_seconds 초 안의 요청 수를 limit 개로 제한한다."""

    MAX_KEYS = 10_000  # 키가 너무 많아지면 오래된 기록을 정리해서 메모리를 지킨다.

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """허용이면 True (이번 요청도 셈에 넣는다), 초과면 False."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) >= self.MAX_KEYS:
                self._cleanup(now)
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def retry_after(self, key: str) -> int:
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 1
            return max(1, int(self.window - (time.monotonic() - hits[0])) + 1)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def _cleanup(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window]:
            del self._hits[key]
