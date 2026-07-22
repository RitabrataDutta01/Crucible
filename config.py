import os


class ScanConfig:
    TIMEOUT = 10
    USER_AGENT = "Mozilla/5.0 (Crucible/0.1)"
    MAX_REDIRECTS = 5
    RATE_LIMIT_DELAY = 0.2
    CRAWL_MAX_DEPTH = 2
    THREAD_WORKERS = 10
    FOLLOW_ROBOTS_TXT = True
    SESSION_EXPIRY_KEYWORDS = ["login", "signin", "session expired", "unauthorized", "auth"]

    @classmethod
    def from_env(cls):
        cls.TIMEOUT = int(os.getenv("CRUCIBLE_TIMEOUT", str(cls.TIMEOUT)))
        cls.CRAWL_MAX_DEPTH = int(os.getenv("CRUCIBLE_CRAWL_DEPTH", str(cls.CRAWL_MAX_DEPTH)))
        cls.RATE_LIMIT_DELAY = float(os.getenv("CRUCIBLE_RATE_LIMIT", str(cls.RATE_LIMIT_DELAY)))
        cls.THREAD_WORKERS = int(os.getenv("CRUCIBLE_WORKERS", str(cls.THREAD_WORKERS)))
        return cls
