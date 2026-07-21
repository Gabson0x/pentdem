"""
Reflection Context Classifier — deterministic XSS pre-screen.

A reflected marker is not an XSS. Where it lands decides everything: a marker echoed
inside a <script> block is executable; the same marker in HTML-escaped body text is
inert. This module answers that question with zero dependencies and no model call, so
the XSS detector and the quality gate get a DETERMINISTIC signal instead of a guess:

    payload = recommended_probe(nonce)        # nonce<>"'nonce  (a canary sandwich)
    inject payload, read the response body
    result = classify_reflection(body, nonce)

The metacharacters ride BETWEEN two copies of the nonce, so the parser reads exactly
which of < > " ' the target left un-escaped, with no contamination from the page's own
markup. It reports the syntactic CONTEXT, the surviving metacharacters, and a verdict
(executable / needs_breakout / inert). Feed it to the quality gate: a `not_reflected`
or `inert` verdict rejects the candidate before it wastes a payload or a report line.

Author: Valisthea (github.com/Valisthea)
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


PROBE_CHARS = ("<", ">", '"', "'")

# HTML-entity encodings a defence might apply to each probe char (named / decimal / hex).
_ENTITIES = {
    "<": ("&lt;", "&#60;", "&#x3c;"),
    ">": ("&gt;", "&#62;", "&#x3e;"),
    '"': ("&quot;", "&#34;", "&#x22;"),
    "'": ("&#39;", "&#x27;", "&apos;"),
}

# Verdicts, worst-first.
EXECUTABLE = "executable"          # reaches JS/HTML execution as-is
NEEDS_BREAKOUT = "needs_breakout"  # reflected + a raw metacharacter, but not directly executable
INERT = "inert"                    # reflected but every break-out char is escaped -> not exploitable
NOT_REFLECTED = "not_reflected"

_MAX_REGION = 64  # a close-canary this far past the open-canary still counts as the same probe


@dataclass
class ReflectionHit:
    context: str                       # script_block | script_string | event_handler | js_uri |
                                       # attr_unquoted | attr_double | attr_single | html_text |
                                       # tag_injection | comment | style
    raw_chars: List[str] = field(default_factory=list)   # probe chars that survived un-escaped here
    executable: bool = False
    detail: str = ""


@dataclass
class ReflectionResult:
    reflected: bool
    count: int
    verdict: str
    hits: List[ReflectionHit] = field(default_factory=list)
    evidence: str = ""

    def as_finding(self, nonce: str) -> Dict:
        """Quality-gate-friendly shape: a COMPUTED confidence + real evidence, never a static default."""
        conf = {EXECUTABLE: 0.95, NEEDS_BREAKOUT: 0.55, INERT: 0.1, NOT_REFLECTED: 0.0}[self.verdict]
        top = self.hits[0] if self.hits else None
        return {
            "vuln_class": "xss",
            "verdict": self.verdict,
            "context": top.context if top else None,
            "raw_chars": top.raw_chars if top else [],
            "confidence": conf,
            "evidence": self.evidence,
            "nonce": nonce,
        }


def recommended_probe(nonce: str) -> str:
    """The value to inject: the four probe chars sandwiched between two copies of the nonce, so the
    metacharacters are read from a bounded region and the page's own markup cannot contaminate it."""
    return nonce + "".join(PROBE_CHARS) + nonce


def _raw_from_region(region: str) -> List[str]:
    """Which probe chars survived un-escaped in the between-canaries region (order-independent)."""
    raw: List[str] = []
    i = 0
    while i < len(region):
        c = region[i]
        if c in PROBE_CHARS:
            if c not in raw:
                raw.append(c)
            i += 1
            continue
        low = region[i:].lower()
        step = next((len(ent) for ents in _ENTITIES.values() for ent in ents if low.startswith(ent)), 0)
        i += step if step else 1
    return raw


def _in_js_string(js: str) -> Optional[str]:
    """The quote char if the tail of `js` is inside an un-terminated ' " or ` string, else None."""
    q = None
    i = 0
    while i < len(js):
        c = js[i]
        if c == "\\":
            i += 2
            continue
        if q is None and c in ("'", '"', "`"):
            q = c
        elif c == q:
            q = None
        i += 1
    return q


def _last_attr(tag: str) -> Optional[str]:
    m = list(re.finditer(r"([a-zA-Z_:][-a-zA-Z0-9_:]*)\s*=", tag))
    return m[-1].group(1).lower() if m else None


def _attr_quote_state(tag: str) -> Optional[str]:
    """The still-open quote of the attribute value the marker sits in, or None if the value is unquoted."""
    m = list(re.finditer(r"=\s*(\"|')", tag))
    if not m:
        return None
    q = m[-1].group(1)
    rest = tag[m[-1].end():]
    return q if q not in rest else None


def _in_tag_name(tag: str, nonce: str) -> bool:
    return bool(re.match(r"<\s*[^\s>]*" + re.escape(nonce), tag))


def _looks_js_uri(tag: str) -> bool:
    return "javascript:" in tag.lower() or bool(re.search(r"=\s*[\"']?\s*$", tag))


def _classify(before: str, raw: List[str], nonce: str) -> ReflectionHit:
    """Classify one reflection: the container from the bytes BEFORE it, executability from `raw`."""
    s_open = before.rfind("<script")
    if s_open != -1 and before.find("</script", s_open) == -1:
        head = before.find(">", s_open)
        q = _in_js_string(before[head + 1:] if head != -1 else "")
        if q:
            return ReflectionHit("script_string", raw, q in raw,
                                 f"inside a {q}-quoted JS string; break-out needs a raw {q}")
        return ReflectionHit("script_block", raw, True, "directly inside a <script> block (JS executable)")

    c_open = before.rfind("<!--")
    if c_open != -1 and before.find("-->", c_open) == -1:
        return ReflectionHit("comment", raw, "<" in raw and ">" in raw,
                             "inside an HTML comment; needs --> then a raw < to break out")

    if before.rfind("<") > before.rfind(">"):
        tag = before[before.rfind("<"):]
        attr = _last_attr(tag)
        quote = _attr_quote_state(tag)
        if attr and attr.startswith("on"):
            return ReflectionHit("event_handler", raw, True, f"inside the {attr} event handler (a JS sink)")
        if attr in ("href", "src", "action", "formaction") and _looks_js_uri(tag):
            return ReflectionHit("js_uri", raw, True, f"inside a javascript:-capable {attr} URI")
        if quote == '"':
            return ReflectionHit("attr_double", raw, '"' in raw, 'double-quoted attribute; needs a raw "')
        if quote == "'":
            return ReflectionHit("attr_single", raw, "'" in raw, "single-quoted attribute; needs a raw '")
        if _in_tag_name(tag, nonce):
            return ReflectionHit("tag_injection", raw, "<" in raw, "reflected as/adjacent to a tag name")
        return ReflectionHit("attr_unquoted", raw, True, "unquoted attribute value (inject a new handler)")

    st_open = before.rfind("<style")
    if st_open != -1 and before.find("</style", st_open) == -1:
        return ReflectionHit("style", raw, False, "inside a <style> block (CSS; rarely direct JS exec)")

    return ReflectionHit("html_text", raw, "<" in raw and ">" in raw,
                         "in HTML body text; executable only if < and > reflect raw (inject a <script>)")


def _pairs(positions: List[int], nlen: int) -> List[Tuple[int, Optional[int]]]:
    """Pair open/close canaries: an open at p, a close at the next position within _MAX_REGION."""
    out: List[Tuple[int, Optional[int]]] = []
    i = 0
    while i < len(positions):
        op = positions[i]
        if i + 1 < len(positions) and positions[i + 1] - (op + nlen) <= _MAX_REGION:
            out.append((op, positions[i + 1]))
            i += 2
        else:
            out.append((op, None))
            i += 1
    return out


def classify_reflection(body: str, nonce: str) -> ReflectionResult:
    """Classify every reflection of `nonce` in `body`. Deterministic; no network, no model."""
    if not body or not nonce or nonce not in body:
        return ReflectionResult(reflected=False, count=0, verdict=NOT_REFLECTED)
    positions = [m.start() for m in re.finditer(re.escape(nonce), body)]
    hits: List[ReflectionHit] = []
    for op, close in _pairs(positions, len(nonce)):
        region = body[op + len(nonce): close] if close is not None else ""
        hits.append(_classify(body[:op], _raw_from_region(region), nonce))
    if any(h.executable for h in hits):
        verdict = EXECUTABLE
    elif any(h.raw_chars for h in hits):
        verdict = NEEDS_BREAKOUT
    else:
        verdict = INERT
    ev = body.find(nonce)
    evidence = body[max(0, ev - 32): ev + len(nonce) + 40]
    hits.sort(key=lambda h: (not h.executable, not h.raw_chars))
    return ReflectionResult(reflected=True, count=len(hits), verdict=verdict, hits=hits, evidence=evidence)


def _selftest() -> int:
    n = "oz1337"
    p = recommended_probe(n)                       # nonce<>"'nonce  (raw metacharacters)
    enc = f"{n}&lt;&gt;&quot;&#39;{n}"              # the probe fully HTML-encoded between the canaries
    cases = {
        "script_block":    (f"<script>var x = {p};</script>", EXECUTABLE),
        "script_str_enc":  (f"<script>var x = 'a{enc}';</script>", INERT),      # trapped in a string, no raw quote
        "script_str_raw":  (f"<script>var x = 'a{p}';</script>", EXECUTABLE),   # raw ' breaks the string
        "event_handler":   (f'<div onclick="f({p})">x</div>', EXECUTABLE),
        "attr_double_enc": (f'<input value="{enc}">', INERT),
        "attr_double_raw": (f'<input value="{p}">', EXECUTABLE),                # raw " breaks the attribute
        "attr_single_enc": (f"<input value='{enc}'>", INERT),
        "attr_unquoted":   (f"<input value={p} >", EXECUTABLE),
        "html_text_enc":   (f"<p>hi {enc}</p>", INERT),
        "html_text_raw":   (f"<p>hi {p}</p>", EXECUTABLE),                      # raw < and > -> inject a tag
        "comment_enc":     (f"<!-- {enc} -->", INERT),
        "not_reflected":   ("<p>nothing here</p>", NOT_REFLECTED),
    }
    for name, (body, want) in cases.items():
        got = classify_reflection(body, n).verdict
        assert got == want, f"{name}: expected {want}, got {got}   ({body!r})"
    assert recommended_probe("abc") == "abc<>\"'abc"
    f = classify_reflection(f"<script>{p}</script>", n).as_finding(n)
    assert f["vuln_class"] == "xss" and f["confidence"] == 0.95 and n in f["evidence"]
    # a single, probe-less reflection cannot pair -> no raw survivors -> never a false 'executable' in text
    assert classify_reflection(f"<p>{n}</p>", n).verdict == INERT
    print("reflection_context selftest: OK — script/attr/event/comment/text contexts; raw-vs-escaped "
          "metacharacters read from a bounded canary sandwich; executable/needs_breakout/inert verdict; "
          "quality-gate finding shape; conservative on a plain reflection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
