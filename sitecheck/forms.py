"""
Shared form/parameter discovery used by the CSRF, XSS and SQLi modules.

Pure stdlib HTML parsing (html.parser) so there is no extra dependency.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qsl
from .core import ScanContext


@dataclass
class Form:
    action: str
    method: str = "get"
    inputs: dict[str, str] = field(default_factory=dict)   # name -> default value
    has_csrf_token: bool = False
    source_url: str = ""


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[Form] = []
        self._cur: Form | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = Form(action=a.get("action", ""),
                             method=(a.get("method") or "get").lower())
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if not name:
                return
            self._cur.inputs[name] = a.get("value", "")
            itype = (a.get("type") or "").lower()
            if (itype == "hidden" and _looks_like_token(name)) or _looks_like_token(name):
                self._cur.has_csrf_token = True

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _looks_like_token(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ("csrf", "token", "_token", "authenticity", "nonce", "xsrf"))


def discover_forms(ctx: ScanContext, url: str | None = None) -> list[Form]:
    url = url or ctx.base_url
    resp = ctx.get(url)
    if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
        return []
    parser = _FormParser()
    try:
        parser.feed(resp.text)
    except Exception:
        return []
    for f in parser.forms:
        f.action = urljoin(url, f.action) if f.action else url
        f.source_url = url
    return parser.forms


def query_params(url: str) -> list[str]:
    """Return the parameter names present in a URL's query string."""
    return [k for k, _ in parse_qsl(urlparse(url).query)]
