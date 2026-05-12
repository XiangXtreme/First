import json
import re
import shutil
import subprocess


def beautify_text(text: str, ext: str) -> str:
    ext = ext.lower()
    if ext in (".json", ".map"):
        return json.dumps(json.loads(text), ensure_ascii=False, indent=2) + "\n"
    if ext in (".js", ".ts", ".wxs", ".css", ".wxss", ".html", ".htm", ".wxml"):
        formatted = _prettier_format(text, ext)
        if formatted is not None:
            return _guard_shrinking(text, formatted)
        if ext in (".html", ".htm", ".wxml"):
            return _guard_shrinking(text, beautify_markup(text))
        return _safe_trim_lines(text)
    if ext in (".xml", ".svg"):
        return _guard_shrinking(text, beautify_markup(text))
    return _safe_trim_lines(text)


def _guard_shrinking(original: str, formatted: str) -> str:
    if len(original) > 2000 and len(formatted) < len(original) * 0.9:
        raise ValueError("美化结果明显短于原文件，已取消以避免丢失内容")
    return formatted


def _safe_trim_lines(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.splitlines()).rstrip() + "\n"


def _prettier_format(text: str, ext: str) -> str | None:
    prettier = shutil.which("prettier")
    if not prettier:
        return None
    parser = {
        ".js": "babel",
        ".ts": "typescript",
        ".wxs": "babel",
        ".css": "css",
        ".wxss": "css",
        ".html": "html",
        ".htm": "html",
        ".wxml": "html",
    }.get(ext)
    if not parser:
        return None
    try:
        proc = subprocess.run(
            [prettier, "--parser", parser, "--tab-width", "2", "--print-width", "120"],
            input=text,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
    except Exception:
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout


def split_code_tokens(text: str) -> list:
    tokens = []
    buf = []
    quote = ""
    escape = False
    line_comment = False
    block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            buf.append(ch)
            if ch == "\n":
                tokens.append("".join(buf))
                buf = []
                line_comment = False
            i += 1
            continue

        if block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                block_comment = False
            else:
                i += 1
            continue

        if quote:
            buf.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue

        if ch in ("'", '"', "`"):
            buf.append(ch)
            quote = ch
            i += 1
            continue

        if ch == "/" and nxt in ("/", "*"):
            buf.extend([ch, nxt])
            line_comment = nxt == "/"
            block_comment = nxt == "*"
            i += 2
            continue

        if ch in "{}[]();,<>":
            if "".join(buf).strip():
                tokens.append("".join(buf))
            buf = []
            tokens.append(ch)
            i += 1
            continue

        if ch == "\n":
            if "".join(buf).strip():
                tokens.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    if "".join(buf).strip():
        tokens.append("".join(buf))
    return tokens


def beautify_brace_code(text: str, indent_unit: str = "  ") -> str:
    lines = []
    indent = 0
    current_line = ""

    def emit(line=""):
        stripped = line.strip()
        if stripped:
            lines.append(indent_unit * max(indent, 0) + stripped)

    for tok in split_code_tokens(text):
        stripped = tok.strip()
        if not stripped:
            continue
        if stripped in ("}", "]"):
            if current_line.strip():
                emit(current_line)
                current_line = ""
            indent = max(indent - 1, 0)
            emit(stripped)
            continue
        if stripped == ">":
            current_line += stripped
            emit(current_line)
            current_line = ""
            continue
        if stripped in ("{", "["):
            current_line = (current_line.rstrip() + " " + stripped).strip()
            emit(current_line)
            current_line = ""
            indent += 1
            continue
        if stripped == "<":
            if current_line.strip():
                emit(current_line)
            current_line = stripped
            continue
        if stripped in (";", ","):
            current_line = current_line.rstrip() + stripped
            emit(current_line)
            current_line = ""
            continue
        if stripped == ")":
            current_line += stripped
            continue
        if stripped == "(":
            current_line = current_line.rstrip() + stripped
            continue
        if current_line:
            sep = "" if current_line.endswith(("<", "(", ".", "!", "~")) else " "
            current_line += sep + stripped
        else:
            current_line = stripped

    if current_line.strip():
        emit(current_line)
    return "\n".join(lines).rstrip() + "\n"


def beautify_markup(text: str) -> str:
    protected = {}

    def protect(match):
        key = f"__FIRST_BLOCK_{len(protected)}__"
        protected[key] = match.group(0)
        return key

    text2 = re.sub(r"(?is)<(script|style)\b[^>]*>.*?</\1>", protect, text)
    text2 = re.sub(r">\s*<", ">\n<", text2)
    raw_lines = [ln.strip() for ln in text2.splitlines() if ln.strip()]
    lines = []
    indent = 0
    void_tags = {
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    }
    for line in raw_lines:
        for key, value in protected.items():
            if key in line:
                line = line.replace(key, value.strip())
        lower = line.lower()
        closing = lower.startswith("</")
        tag_match = re.match(r"</?\s*([a-zA-Z0-9_-]+)", line)
        tag = tag_match.group(1).lower() if tag_match else ""
        self_closing = lower.endswith("/>") or tag in void_tags or lower.startswith("<!")
        if closing:
            indent = max(indent - 1, 0)
        lines.append("  " * indent + line)
        if line.startswith("<") and not closing and not self_closing and not lower.startswith("<?"):
            if not re.search(r"</\s*" + re.escape(tag) + r"\s*>$", lower):
                indent += 1
    return "\n".join(lines).rstrip() + "\n"
