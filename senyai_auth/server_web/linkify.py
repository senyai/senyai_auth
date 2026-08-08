from __future__ import annotations
import re
from markupsafe import Markup, escape

URL_RE = re.compile(r"(https?://[^\s<]+)")
EMAIL_RE = re.compile(
    r"(?<![\w.])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)
PHONE_RE = re.compile(r"(\+?\d[\d\s().-]{7,}\d)")
AT_RE = re.compile(r"(?<![\w.])@([A-Za-z0-9_]+)")
TRAILING_PUNCT = ".,!?;:)"


def strip_trailing_punct(s: str) -> tuple[str, str]:
    core = s.rstrip(TRAILING_PUNCT)
    tail = s[len(core) :]
    return core, tail


def linkify(text: str) -> Markup:
    text = escape(text)

    def repl_url(m: re.Match[str]):
        raw = m.group(1)
        url, tail = strip_trailing_punct(raw)
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer"><i class="bi bi-globe"></i> {url}</a>{tail}'

    def repl_email(m: re.Match[str]):
        raw = m.group(1)
        email, tail = strip_trailing_punct(raw)
        return f'<a href="mailto:{email}"><i class="bi bi-envelope-fill"></i> {email}</a>{tail}'

    def repl_phone(m: re.Match[str]):
        raw = m.group(1)
        phone, tail = strip_trailing_punct(raw)
        tel = re.sub(r"[\s().-]", "", phone)
        return f'<a href="tel:{tel}"><i class="bi bi-telephone-fill"></i> {phone}</a>{tail}'

    def repl_at(m: re.Match[str]):
        user = m.group(1)
        return f'<a href="https://t.me/{user}"><i class="bi bi-telegram"></i> @{user}</a>'

    text = URL_RE.sub(repl_url, text)
    text = EMAIL_RE.sub(repl_email, text)
    text = PHONE_RE.sub(repl_phone, text)
    text = AT_RE.sub(repl_at, text)
    text = text.replace("\n", "<br>\n")

    return Markup(text)
