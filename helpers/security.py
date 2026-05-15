"""AI Application Security Module.

Provides defense-in-depth security controls for AI-powered video processing:

  - Input validation and path traversal prevention
  - Safe subprocess execution (command injection prevention)
  - Rate limiting for API and render calls
  - PII detection and redaction
  - Prompt injection detection
  - Structured audit logging
  - File integrity verification
  - Secure temporary file management
  - API key validation

Usage:
    from security import SecurityContext, get_api_key
    ctx = SecurityContext(allowed_root=Path("/data/projects"))
    safe_path = ctx.validate_input_path(user_supplied_path)
    ctx.check_rate_limit("user-session-id")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import tempfile
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

_audit_logger = logging.getLogger("security.audit")


def configure_audit_log(log_path: Path | None = None, level: int = logging.INFO) -> None:
    """Configure the audit logger. Call once at application startup."""
    handler: logging.Handler
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_path)
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s [AUDIT] %(levelname)s %(message)s")
    )
    _audit_logger.addHandler(handler)
    _audit_logger.setLevel(level)
    _audit_logger.propagate = False


def audit(event: str, **kwargs: Any) -> None:
    """Emit a structured audit log entry."""
    payload = json.dumps({"event": event, **kwargs}, default=str)
    _audit_logger.info(payload)


# ---------------------------------------------------------------------------
# Security exceptions
# ---------------------------------------------------------------------------


class SecurityError(Exception):
    """Raised when a security check fails."""


class PathTraversalError(SecurityError):
    """Raised when a path escapes its allowed root."""


class CommandInjectionError(SecurityError):
    """Raised when a command argument contains dangerous patterns."""


class PromptInjectionError(SecurityError):
    """Raised when user input contains suspected prompt injection."""


class RateLimitError(SecurityError):
    """Raised when a caller exceeds their rate limit."""


class FileSizeError(SecurityError):
    """Raised when a file exceeds the allowed size limit."""


class InvalidInputError(SecurityError):
    """Raised when input fails schema or type validation."""


# ---------------------------------------------------------------------------
# Path traversal prevention
# ---------------------------------------------------------------------------

ALLOWED_VIDEO_EXTENSIONS = frozenset({
    ".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v", ".mts", ".m2ts",
})
ALLOWED_AUDIO_EXTENSIONS = frozenset({
    ".mp3", ".wav", ".aac", ".m4a", ".flac", ".ogg",
})
ALLOWED_DATA_EXTENSIONS = frozenset({
    ".json", ".srt", ".vtt", ".txt", ".csv",
})
ALLOWED_EXTENSIONS = (
    ALLOWED_VIDEO_EXTENSIONS | ALLOWED_AUDIO_EXTENSIONS | ALLOWED_DATA_EXTENSIONS
)

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB


def safe_resolve(path: str | Path, allowed_root: Path) -> Path:
    """Resolve `path` and verify it stays within `allowed_root`.

    Raises PathTraversalError if the resolved path escapes the root.
    """
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(allowed_root.resolve())
    except ValueError:
        audit("path_traversal_blocked", path=str(path), root=str(allowed_root))
        raise PathTraversalError(
            f"Path '{path}' escapes allowed root '{allowed_root}'"
        )
    return resolved


def validate_file_extension(
    path: str | Path, allowed: frozenset[str] | None = None
) -> Path:
    """Ensure the path has an allowed file extension."""
    p = Path(path)
    ext = p.suffix.lower()
    check = allowed if allowed is not None else ALLOWED_EXTENSIONS
    if ext not in check:
        raise InvalidInputError(
            f"Extension '{ext}' is not allowed. Allowed: {sorted(check)}"
        )
    return p


def validate_file_size(path: Path, max_bytes: int = MAX_FILE_SIZE_BYTES) -> None:
    """Raise FileSizeError if file exceeds max_bytes."""
    if path.exists():
        size = path.stat().st_size
        if size > max_bytes:
            raise FileSizeError(
                f"File '{path.name}' is {size / (1024 ** 3):.2f} GB, "
                f"exceeds limit of {max_bytes / (1024 ** 3):.0f} GB"
            )


def validate_input_path(
    path: str | Path,
    allowed_root: Path,
    allowed_extensions: frozenset[str] | None = None,
    check_exists: bool = True,
) -> Path:
    """Full input path validation pipeline: root, extension, existence, size."""
    p = safe_resolve(path, allowed_root)
    validate_file_extension(p, allowed_extensions)
    if check_exists and not p.exists():
        raise InvalidInputError(f"File not found: {p}")
    if check_exists and p.exists():
        validate_file_size(p)
    audit("input_validated", path=str(p))
    return p


# ---------------------------------------------------------------------------
# EDL schema validation
# ---------------------------------------------------------------------------

_REQUIRED_EDL_KEYS = {"sources", "ranges"}
_REQUIRED_RANGE_KEYS = {"source", "start", "end"}
_MAX_RANGES = 10_000
_MAX_SEGMENT_DURATION_S = 3600.0


def validate_edl(edl: dict[str, Any], allowed_root: Path) -> None:
    """Validate an EDL dict for required fields, types, and safe paths.

    Raises InvalidInputError if any field is malformed or unsafe.
    """
    if not isinstance(edl, dict):
        raise InvalidInputError("EDL must be a JSON object")

    missing = _REQUIRED_EDL_KEYS - edl.keys()
    if missing:
        raise InvalidInputError(f"EDL missing required keys: {missing}")

    sources = edl["sources"]
    if not isinstance(sources, dict):
        raise InvalidInputError("EDL 'sources' must be an object")

    for name, path in sources.items():
        if not isinstance(name, str) or not re.match(r"^[a-zA-Z0-9_\-]+$", name):
            raise InvalidInputError(
                f"Source name '{name}' must contain only alphanumerics, hyphens, underscores"
            )
        if not isinstance(path, str):
            raise InvalidInputError(f"Source path for '{name}' must be a string")
        validate_file_extension(
            path, ALLOWED_VIDEO_EXTENSIONS | ALLOWED_AUDIO_EXTENSIONS
        )
        safe_resolve(path, allowed_root)

    ranges = edl["ranges"]
    if not isinstance(ranges, list) or len(ranges) == 0:
        raise InvalidInputError("EDL 'ranges' must be a non-empty array")
    if len(ranges) > _MAX_RANGES:
        raise InvalidInputError(f"EDL has too many ranges (max {_MAX_RANGES})")

    for i, r in enumerate(ranges):
        if not isinstance(r, dict):
            raise InvalidInputError(f"Range [{i}] must be an object")
        missing_r = _REQUIRED_RANGE_KEYS - r.keys()
        if missing_r:
            raise InvalidInputError(f"Range [{i}] missing keys: {missing_r}")
        if r["source"] not in sources:
            raise InvalidInputError(
                f"Range [{i}] references unknown source '{r['source']}'"
            )
        try:
            start = float(r["start"])
            end = float(r["end"])
        except (ValueError, TypeError):
            raise InvalidInputError(f"Range [{i}] start/end must be numbers")
        if start < 0 or end < 0:
            raise InvalidInputError(f"Range [{i}] timestamps must be non-negative")
        if end <= start:
            raise InvalidInputError(
                f"Range [{i}] end ({end}) must be greater than start ({start})"
            )
        if end - start > _MAX_SEGMENT_DURATION_S:
            raise InvalidInputError(
                f"Range [{i}] duration exceeds {_MAX_SEGMENT_DURATION_S}s"
            )


# ---------------------------------------------------------------------------
# Command injection prevention
# ---------------------------------------------------------------------------

# Shell metacharacters that should never appear in subprocess args
_SHELL_METACHARACTERS = re.compile(r"[;&|`$<>\\\n\r\x00]")
_NULL_BYTE = re.compile(r"\x00")

# Only these binaries may be invoked
ALLOWED_BINARIES = frozenset({"ffmpeg", "ffprobe"})

# Safe characters for ffmpeg filter strings
_SAFE_FILTER_RE = re.compile(r"^[a-zA-Z0-9_.,:=/+\-@\[\]{}() \t'\\]*$")


def validate_binary(binary: str) -> None:
    """Ensure only allowed binaries are invoked."""
    name = Path(binary).name
    if name not in ALLOWED_BINARIES:
        audit("disallowed_binary_blocked", binary=binary)
        raise CommandInjectionError(
            f"Binary '{binary}' not in allowlist: {ALLOWED_BINARIES}"
        )


def sanitize_filter_string(filter_str: str, max_len: int = 4096) -> str:
    """Validate that an ffmpeg filter string contains only safe characters."""
    if _NULL_BYTE.search(filter_str):
        raise CommandInjectionError("Filter string contains null byte")
    if len(filter_str) > max_len:
        raise CommandInjectionError(
            f"Filter string length {len(filter_str)} exceeds maximum {max_len}"
        )
    if not _SAFE_FILTER_RE.match(filter_str):
        bad = set(re.findall(r"[^a-zA-Z0-9_.,:=/+\-@\[\]{}() \t'\\]", filter_str))
        raise CommandInjectionError(
            f"Filter string contains disallowed characters: {bad}"
        )
    return filter_str


def build_safe_ffmpeg_cmd(args: list[str]) -> list[str]:
    """Validate an ffmpeg command list before execution.

    Checks:
    - First element is an allowed binary
    - No shell metacharacters in any argument
    - No null bytes
    - All arguments are strings
    """
    if not args:
        raise CommandInjectionError("Empty command")
    validate_binary(args[0])
    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            raise CommandInjectionError(
                f"Argument [{i}] is not a string: {arg!r}"
            )
        if _NULL_BYTE.search(arg):
            raise CommandInjectionError(f"Argument [{i}] contains null byte")
        if _SHELL_METACHARACTERS.search(arg):
            raise CommandInjectionError(
                f"Argument [{i}] contains shell metacharacter: {arg!r}"
            )
    return args


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@dataclass
class RateLimiter:
    """Token-bucket rate limiter keyed by caller identity.

    Args:
        max_calls: Maximum calls allowed per window.
        window_seconds: Rolling window duration in seconds.
    """

    max_calls: int = 60
    window_seconds: float = 60.0
    _buckets: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def check(self, key: str) -> None:
        """Raise RateLimitError if `key` has exceeded the rate limit."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        self._buckets[key] = [
            t for t in self._buckets[key] if t > cutoff
        ]
        if len(self._buckets[key]) >= self.max_calls:
            audit(
                "rate_limit_exceeded",
                key=key,
                count=len(self._buckets[key]),
                limit=self.max_calls,
            )
            raise RateLimitError(
                f"Rate limit exceeded: {self.max_calls} calls "
                f"per {self.window_seconds:.0f}s for key '{key}'"
            )
        self._buckets[key].append(now)

    def reset(self, key: str) -> None:
        """Clear the rate limit bucket for a key (testing/admin use)."""
        self._buckets.pop(key, None)


# Module-level limiters — override via SecurityContext for custom limits
api_rate_limiter = RateLimiter(max_calls=100, window_seconds=60.0)
render_rate_limiter = RateLimiter(max_calls=10, window_seconds=60.0)


# ---------------------------------------------------------------------------
# PII detection and redaction
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    )),
    ("phone_us", re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    )),
    ("ssn", re.compile(
        r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"
    )),
    ("credit_card", re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    )),
    ("anthropic_key", re.compile(
        r"\bsk-ant-[a-zA-Z0-9\-_]{32,}\b"
    )),
    ("openai_key", re.compile(
        r"\bsk-[a-zA-Z0-9]{48}\b"
    )),
    ("generic_api_key", re.compile(
        r"\b(?:sk|pk|api|key|token|secret)[-_][a-zA-Z0-9]{20,}\b",
        re.IGNORECASE,
    )),
    ("aws_access_key", re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    )),
    ("github_token", re.compile(
        r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b"
    )),
]

_REDACTION_PLACEHOLDER = "[REDACTED]"

_SECRET_TYPES = {
    "anthropic_key", "openai_key", "generic_api_key",
    "aws_access_key", "github_token",
}


def detect_pii(text: str) -> list[tuple[str, str]]:
    """Return list of (pii_type, matched_value) tuples found in `text`."""
    found: list[tuple[str, str]] = []
    for pii_type, pattern in _PII_PATTERNS:
        for match in pattern.finditer(text):
            found.append((pii_type, match.group()))
    return found


def redact_pii(text: str) -> str:
    """Replace all detected PII patterns in `text` with [REDACTED]."""
    result = text
    for _, pattern in _PII_PATTERNS:
        result = pattern.sub(_REDACTION_PLACEHOLDER, result)
    return result


def check_for_secrets(text: str, context: str = "") -> None:
    """Audit-log any PII or secrets detected. Raise SecurityError for API keys."""
    findings = detect_pii(text)
    if not findings:
        return
    types_found = [t for t, _ in findings]
    audit("pii_detected", context=context, types=types_found)
    leaked = [t for t in types_found if t in _SECRET_TYPES]
    if leaked:
        raise SecurityError(
            f"Potential API key or secret detected in {context or 'input'} "
            f"(types: {leaked}). Remove secrets before processing."
        )


# ---------------------------------------------------------------------------
# Prompt injection detection
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(
        r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.IGNORECASE
    )),
    ("forget_instructions", re.compile(
        r"\bforget\s+(your\s+)?instructions?\b", re.IGNORECASE
    )),
    ("role_override", re.compile(
        r"\byou\s+are\s+now\s+(?:a|an|DAN|GPT|Claude)\b", re.IGNORECASE
    )),
    ("act_as", re.compile(
        r"\bact\s+as\s+(?:if|an?)\b", re.IGNORECASE
    )),
    ("system_tag", re.compile(
        r"<\s*(?:system|SYS|SYSTEM)\s*>", re.IGNORECASE
    )),
    ("llm_delimiter", re.compile(
        r"\[INST\]|\[\/INST\]", re.IGNORECASE
    )),
    ("instruction_override", re.compile(
        r"###\s*(?:system|instruction|override)", re.IGNORECASE
    )),
    ("prompt_exfil", re.compile(
        r"\bprint\s+(?:your\s+)?(?:system\s+)?prompt\b", re.IGNORECASE
    )),
    ("reveal_prompt", re.compile(
        r"\breveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\b",
        re.IGNORECASE,
    )),
    ("repeat_above", re.compile(
        r"\brepeat\s+(?:everything|all)\s+(?:above|before)\b", re.IGNORECASE
    )),
    ("developer_mode", re.compile(
        r"\bdeveloper\s+mode\b", re.IGNORECASE
    )),
    ("jailbreak", re.compile(
        r"\bjailbreak\b", re.IGNORECASE
    )),
    ("override_safety", re.compile(
        r"\boverride\s+(?:safety|content|policy|filter)\b", re.IGNORECASE
    )),
]


def detect_prompt_injection(text: str) -> list[tuple[str, str]]:
    """Return list of (pattern_name, matched_text) tuples found in `text`."""
    matches: list[tuple[str, str]] = []
    for name, pattern in _INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            matches.append((name, m.group()))
    return matches


def validate_prompt_input(text: str, field_name: str = "input") -> str:
    """Check for prompt injection. Raises PromptInjectionError if found.

    Also enforces a maximum length to prevent context-flooding attacks.
    """
    if not isinstance(text, str):
        raise InvalidInputError(f"Field '{field_name}' must be a string")
    if len(text) > 50_000:
        raise InvalidInputError(
            f"Field '{field_name}' exceeds maximum length of 50,000 characters"
        )
    matches = detect_prompt_injection(text)
    if matches:
        names = [n for n, _ in matches]
        audit("prompt_injection_detected", field=field_name, patterns=names[:5])
        raise PromptInjectionError(
            f"Potential prompt injection detected in '{field_name}': "
            f"{names[:3]}"
        )
    return text


# ---------------------------------------------------------------------------
# Secure temporary file management
# ---------------------------------------------------------------------------


@contextmanager
def secure_temp_dir(prefix: str = "video_sec_") -> Iterator[Path]:
    """Context manager that creates and cleans up a secure temporary directory.

    Permissions are set to 0o700 (owner only).
    """
    tmp = tempfile.mkdtemp(prefix=prefix)
    tmp_path = Path(tmp)
    try:
        tmp_path.chmod(0o700)
        yield tmp_path
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# File integrity
# ---------------------------------------------------------------------------


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path: Path, expected: str) -> None:
    """Raise SecurityError if the file's SHA-256 does not match expected."""
    actual = compute_sha256(path)
    if not hmac.compare_digest(actual, expected.lower()):
        audit("integrity_check_failed", path=str(path))
        raise SecurityError(
            f"Integrity check failed for '{path.name}': "
            f"expected {expected[:16]}…, got {actual[:16]}…"
        )
    audit("integrity_check_passed", path=str(path))


# ---------------------------------------------------------------------------
# API key validation
# ---------------------------------------------------------------------------


def validate_anthropic_key(key: str) -> None:
    """Raise SecurityError if the key doesn't match the Anthropic key format."""
    if not key:
        raise SecurityError("ANTHROPIC_API_KEY is not set")
    if not key.startswith("sk-ant-"):
        raise SecurityError(
            "ANTHROPIC_API_KEY does not have expected 'sk-ant-' prefix"
        )
    if len(key) < 40:
        raise SecurityError(
            "ANTHROPIC_API_KEY is too short to be valid"
        )


def get_api_key(env_var: str = "ANTHROPIC_API_KEY") -> str:
    """Retrieve an API key from the environment only — never from source files."""
    key = os.environ.get(env_var, "")
    if not key:
        raise SecurityError(
            f"Environment variable '{env_var}' is not set. "
            "Never hardcode API keys in source files."
        )
    if env_var == "ANTHROPIC_API_KEY":
        validate_anthropic_key(key)
    return key


# ---------------------------------------------------------------------------
# Security context
# ---------------------------------------------------------------------------


@dataclass
class SecurityContext:
    """Configured security context for a processing session.

    Centralises all security controls so call sites interact with one
    object rather than importing individual functions.

    Usage:
        ctx = SecurityContext(allowed_root=Path("/data/projects"))
        edl_path = ctx.validate_input_path(user_path)
        ctx.validate_edl(edl)
        ctx.check_rate_limit(session_id)
    """

    allowed_root: Path
    max_file_size_bytes: int = MAX_FILE_SIZE_BYTES
    enable_prompt_injection_check: bool = True
    enable_pii_check: bool = True
    api_limiter: RateLimiter = field(
        default_factory=lambda: api_rate_limiter
    )
    render_limiter: RateLimiter = field(
        default_factory=lambda: render_rate_limiter
    )

    def validate_input_path(
        self,
        path: str | Path,
        allowed_extensions: frozenset[str] | None = None,
        check_exists: bool = True,
    ) -> Path:
        return validate_input_path(
            path, self.allowed_root, allowed_extensions, check_exists
        )

    def validate_edl(self, edl: dict[str, Any]) -> None:
        validate_edl(edl, self.allowed_root)

    def check_rate_limit(self, key: str, limiter: str = "api") -> None:
        if limiter == "render":
            self.render_limiter.check(key)
        else:
            self.api_limiter.check(key)

    def scan_text(
        self, text: str, field_name: str = "input"
    ) -> str:
        """Run PII and prompt-injection checks on a text field."""
        if self.enable_pii_check:
            check_for_secrets(text, context=field_name)
        if self.enable_prompt_injection_check:
            validate_prompt_input(text, field_name)
        return text

    def build_ffmpeg_cmd(self, args: list[str]) -> list[str]:
        return build_safe_ffmpeg_cmd(args)

    def secure_temp(self, prefix: str = "video_sec_") -> Any:
        return secure_temp_dir(prefix)
