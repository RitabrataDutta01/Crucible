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

    @staticmethod
    def from_env():
        config = ScanConfig()
        config.TIMEOUT = int(os.getenv("CRUCIBLE_TIMEOUT", str(config.TIMEOUT)))
        config.CRAWL_MAX_DEPTH = int(os.getenv("CRUCIBLE_CRAWL_DEPTH", str(config.CRAWL_MAX_DEPTH)))
        config.RATE_LIMIT_DELAY = float(os.getenv("CRUCIBLE_RATE_LIMIT", str(config.RATE_LIMIT_DELAY)))
        config.THREAD_WORKERS = int(os.getenv("CRUCIBLE_WORKERS", str(config.THREAD_WORKERS)))
        return config
