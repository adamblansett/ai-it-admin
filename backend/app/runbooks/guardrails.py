import re

FORBIDDEN_SHELL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("destructive_rm", re.compile(r"(?i)\brm\s+-[a-z]*[rf][a-z]*\b")),
    ("disk_format_mkfs", re.compile(r"(?i)\bmkfs(?:\.[a-z0-9]+)?\b")),
    ("raw_block_write_dd", re.compile(r"(?i)\bdd\s+if=")),
    ("remote_pipe_shell", re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|da)?sh\b")),
    ("world_writable_chmod", re.compile(r"(?i)\bchmod\s+(?:-R\s+)?0?777\b")),
    ("sql_drop_object", re.compile(r"(?i)\bdrop\s+(?:database|table|schema)\b")),
    ("kube_delete_namespace", re.compile(r"(?i)\bkubectl\s+delete\s+(?:ns|namespace)\b")),
    ("host_power_control", re.compile(r"(?i)\b(?:shutdown|reboot|poweroff|init\s+0)\b")),
    ("dynamic_eval", re.compile(r"(?i)\beval\s+")),
    ("command_substitution", re.compile(r"\$\([^)]+\)")),
    ("backtick_execution", re.compile(r"`[^`\n]{2,}`")),
)

BLOCKED_COMMAND_MARKER = "[BLOCKED BY ZERO-BLIND-SHELL GUARDRAIL]"


def inspect_commands_for_safety(texts: list[str]) -> tuple[list[str], list[str]]:
    """Scan command candidates and inputs for unsafe blind-execution shell patterns."""
    safe_texts: list[str] = []
    blocked_descriptions: list[str] = []
    seen_blocked: set[str] = set()

    for item in texts:
        matched_labels: list[str] = []
        for label, pattern in FORBIDDEN_SHELL_PATTERNS:
            if pattern.search(item):
                matched_labels.append(label)

        if matched_labels:
            safe_texts.append(BLOCKED_COMMAND_MARKER)
            summary = f"{','.join(matched_labels)}: {item.strip()[:80]}"
            if summary not in seen_blocked:
                seen_blocked.add(summary)
                blocked_descriptions.append(summary)
        else:
            safe_texts.append(item)

    return safe_texts, blocked_descriptions
