---
name: security
description: "AI application security controls for video processing. Apply when handling untrusted input paths, EDL files from users, subprocess construction, API key management, rate limiting, PII scanning, or prompt injection prevention. Integrates with helpers/security.py."
user-invokable: false
---

# AI App Security Skill

This skill teaches Claude how to apply the `helpers/security.py` module when
processing user-supplied data in the video pipeline.

## When to Apply

- User provides a file path → validate with `ctx.validate_input_path()`
- User provides an EDL JSON → parse then call `ctx.validate_edl()`
- Building an ffmpeg command → call `ctx.build_ffmpeg_cmd()`
- Calling the Anthropic API → call `get_api_key()` + `ctx.check_rate_limit()`
- Any free-text user note/instruction in EDL → call `ctx.scan_text()`

## Setup

```python
from pathlib import Path
from security import SecurityContext, RateLimiter, get_api_key
from security_config import get_context

# Use environment-driven defaults (recommended)
ctx = get_context()

# Or build explicitly
ctx = SecurityContext(
    allowed_root=Path("/data/projects"),
)
```

## Input Path Validation

Always validate user-supplied paths before passing to ffmpeg or the filesystem.

```python
from security import ALLOWED_VIDEO_EXTENSIONS

# Validates: path stays within allowed_root, extension is video, file exists, size ≤ 10 GB
safe_path = ctx.validate_input_path(
    user_supplied_path,
    allowed_extensions=ALLOWED_VIDEO_EXTENSIONS,
)
```

**What it blocks:**
- `../../etc/passwd` — path traversal
- `/proc/self/mem` — system files outside root
- `file.php` — disallowed extensions
- Symlinks that escape the root
- Files > 10 GB

## EDL Validation

```python
import json
from pathlib import Path
from security import validate_edl, InvalidInputError

edl_path = ctx.validate_input_path(user_path, allowed_extensions=frozenset({".json"}))
try:
    edl = json.loads(edl_path.read_text())
except json.JSONDecodeError as e:
    raise InvalidInputError(f"EDL is not valid JSON: {e}") from e

ctx.validate_edl(edl)  # checks schema, source names, timestamps, path safety
```

**What it blocks:**
- Missing required fields (`sources`, `ranges`)
- Source names with shell metacharacters
- Source paths outside allowed root
- Negative or inverted timestamps
- Segments longer than 1 hour
- More than 10,000 ranges

## Safe Subprocess Construction

```python
# Always use build_safe_ffmpeg_cmd before subprocess.run
cmd = ctx.build_ffmpeg_cmd([
    "ffmpeg", "-y", "-i", str(safe_path),
    "-c", "copy", str(out_path),
])
subprocess.run(cmd, check=True)
```

**What it blocks:**
- Non-allowlisted binaries (`bash`, `sh`, `python`, etc.)
- Shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `<`, `>`)
- Null bytes in arguments
- Non-string arguments

## Rate Limiting

```python
# Check before expensive operations
ctx.check_rate_limit(session_id, limiter="api")     # 100 calls/min
ctx.check_rate_limit(session_id, limiter="render")  # 10 jobs/min
```

Defaults are configurable via `VIDEO_SECURITY_RATE_API` and `VIDEO_SECURITY_RATE_RENDER`.

## PII and Secret Detection

```python
# Raises SecurityError if API keys are found; audit-logs other PII
ctx.scan_text(user_note, field_name="EDL note")

# For output — redact before logging or displaying to users
from security import redact_pii
safe_output = redact_pii(model_response)
```

**Detected types:** email, US phone, SSN, credit card, Anthropic/OpenAI/AWS/GitHub tokens.

## Prompt Injection Prevention

```python
# Validates user-supplied text before it reaches an LLM
clean_instruction = ctx.scan_text(user_instruction, field_name="instruction")
# PromptInjectionError raised if injection patterns found
```

**Detected patterns:** `ignore previous instructions`, `jailbreak`, `<system>` tags,
`[INST]` delimiters, `developer mode`, prompt exfiltration attempts.

## API Key Management

```python
from security import get_api_key

# Always load from environment, never from config files or source code
api_key = get_api_key("ANTHROPIC_API_KEY")
```

Raises `SecurityError` if the key is missing or doesn't match the expected format.

## Audit Logging

All security events are emitted automatically. Configure the log destination:

```bash
export VIDEO_SECURITY_AUDIT_LOG=/var/log/video-app/audit.log
```

Or in code:

```python
from security import configure_audit_log, audit
from pathlib import Path

configure_audit_log(Path("/var/log/video-app/audit.log"))

# Emit custom events
audit("render_started", edl=str(edl_path), session=session_id)
```

Audit log format (structured JSON per line):
```
2026-05-15 12:00:00,000 [AUDIT] INFO {"event": "input_validated", "path": "/data/projects/clip.mp4"}
2026-05-15 12:00:01,000 [AUDIT] WARNING {"event": "path_traversal_blocked", "path": "../../etc/passwd"}
```

## File Integrity

```python
from security import compute_sha256, verify_sha256

# Before processing a file
digest = compute_sha256(safe_path)

# After transfer / storage — verify nothing changed
verify_sha256(downloaded_path, expected_digest)
```

## Secure Temp Files

```python
with ctx.secure_temp(prefix="render_") as tmp_dir:
    # tmp_dir has 0o700 permissions, auto-cleaned on exit
    work_file = tmp_dir / "intermediate.mp4"
    # ... processing ...
# tmp_dir and all contents deleted here
```

## Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `VIDEO_SECURITY_ROOT` | `cwd` | Allowed file root for all path validation |
| `VIDEO_SECURITY_MAX_FILE_GB` | `10` | Max input file size in GB |
| `VIDEO_SECURITY_RATE_API` | `100` | Max API calls per minute |
| `VIDEO_SECURITY_RATE_RENDER` | `10` | Max render jobs per minute |
| `VIDEO_SECURITY_AUDIT_LOG` | stderr | Audit log file path |

## Common Mistakes to Avoid

| Wrong | Right |
|---|---|
| `subprocess.run(["ffmpeg", user_filter])` | `ctx.build_ffmpeg_cmd(["ffmpeg", user_filter])` |
| `Path(user_input).resolve()` | `ctx.validate_input_path(user_input)` |
| `api_key = config["key"]` | `get_api_key("ANTHROPIC_API_KEY")` |
| `os.system(f"ffmpeg -i {path}")` | Always use `subprocess.run` with a list, validated by `build_safe_ffmpeg_cmd` |
| Logging raw user input | `redact_pii(user_input)` before logging |
