"""Environment-driven security configuration.

Override defaults via environment variables:

  VIDEO_SECURITY_MAX_FILE_GB   max input file size in GB      (default: 10)
  VIDEO_SECURITY_RATE_API      max API calls per minute       (default: 100)
  VIDEO_SECURITY_RATE_RENDER   max render jobs per minute     (default: 10)
  VIDEO_SECURITY_AUDIT_LOG     path to audit log file         (default: stderr)
  VIDEO_SECURITY_ROOT          allowed file root directory    (default: cwd)
"""

from __future__ import annotations

import os
from pathlib import Path

from security import RateLimiter, SecurityContext, configure_audit_log


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_path(name: str, default: Path) -> Path:
    val = os.environ.get(name)
    return Path(val) if val else default


def build_default_context() -> SecurityContext:
    """Build a SecurityContext from environment variables."""
    max_gb = _env_int("VIDEO_SECURITY_MAX_FILE_GB", 10)
    rate_api = _env_int("VIDEO_SECURITY_RATE_API", 100)
    rate_render = _env_int("VIDEO_SECURITY_RATE_RENDER", 10)
    allowed_root = _env_path("VIDEO_SECURITY_ROOT", Path.cwd())
    audit_log_str = os.environ.get("VIDEO_SECURITY_AUDIT_LOG", "")
    audit_log: Path | None = Path(audit_log_str) if audit_log_str else None

    configure_audit_log(audit_log)

    return SecurityContext(
        allowed_root=allowed_root,
        max_file_size_bytes=max_gb * 1024 ** 3,
        api_limiter=RateLimiter(max_calls=rate_api, window_seconds=60.0),
        render_limiter=RateLimiter(max_calls=rate_render, window_seconds=60.0),
    )


_default_ctx: SecurityContext | None = None


def get_context() -> SecurityContext:
    """Return the module-level default SecurityContext (lazy-initialized)."""
    global _default_ctx
    if _default_ctx is None:
        _default_ctx = build_default_context()
    return _default_ctx
