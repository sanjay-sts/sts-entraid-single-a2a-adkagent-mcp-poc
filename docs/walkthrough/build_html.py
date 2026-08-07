"""Build styled HTML versions of the walkthrough markdown files.

Run from anywhere:
    uv run --with markdown --with pygments python docs/walkthrough/build_html.py

Outputs *.html next to the *.md sources so every relative link
(assets/, scripts/, ../../README.md) keeps resolving. Re-run after
editing any .md file; outputs are fully regenerated each time.
"""

from __future__ import annotations

import html as html_mod
import re
from pathlib import Path

import markdown

HERE = Path(__file__).parent

# (md filename, output filename, sidebar label)
PAGES = [
    ("README.md", "index.html", "Home — start here"),
    ("00-big-picture.md", "00-big-picture.html", "Act 00 — The big picture"),
    ("01-golden-thread.md", "01-golden-thread.html", "Act 01 — Golden thread"),
    ("02-denials-by-gate.md", "02-denials-by-gate.html", "Act 02 — Denials by gate"),
    ("03-mcp-security.md", "03-mcp-security.html", "Act 03 — MCP security"),
    ("04-agent-tier-setup.md", "04-agent-tier-setup.html", "Act 04 — Agent-tier setup"),
    ("05-machine-chain.md", "05-machine-chain.html", "Act 05 — Machine chain"),
    ("06-delegated-chain.md", "06-delegated-chain.html", "Act 06 — Delegated chain"),
    ("07-adversarial.md", "07-adversarial.html", "Act 07 — Adversarial"),
    ("08-orchestration-security.md", "08-orchestration-security.html", "Act 08 — Orchestration security"),
    ("09-cognito.md", "09-cognito.html", "Act 09 — Cognito"),
    ("CODE-TOUR.md", "CODE-TOUR.html", "Code tour"),
]

MD_TO_HTML = {md: out for md, out, _ in PAGES}

MERMAID_FENCE = re.compile(r"^```mermaid\s*\n(.*?)^```\s*$", re.M | re.S)
# Only rewrite bare same-folder links like (00-big-picture.md) or (CODE-TOUR.md#x);
# links containing a slash (../../README.md, scripts/foo.py) are left alone.
LOCAL_MD_LINK = re.compile(r"\(([A-Za-z0-9][A-Za-z0-9\-]*\.md)(#[^)]*)?\)")


def extract_mermaid(text: str) -> tuple[str, list[str]]:
    blocks: list[str] = []

    def repl(m: re.Match) -> str:
        blocks.append(m.group(1))
        return f"\n\nMERMAIDBLOCK{len(blocks) - 1}MERMAIDBLOCK\n\n"

    return MERMAID_FENCE.sub(repl, text), blocks


def rewrite_links(text: str) -> str:
    def repl(m: re.Match) -> str:
        target, anchor = m.group(1), m.group(2) or ""
        return f"({MD_TO_HTML.get(target, target)}{anchor})"

    return LOCAL_MD_LINK.sub(repl, text)


def convert(md_text: str) -> str:
    md_text, mermaid_blocks = extract_mermaid(md_text)
    md_text = rewrite_links(md_text)
    body = markdown.markdown(
        md_text,
        extensions=["fenced_code", "codehilite", "tables", "toc", "sane_lists"],
        extension_configs={
            "codehilite": {"guess_lang": False, "css_class": "codehilite"},
            "toc": {"permalink": False},
        },
    )
    for i, src in enumerate(mermaid_blocks):
        placeholder = f"<p>MERMAIDBLOCK{i}MERMAIDBLOCK</p>"
        figure = (
            '<figure class="diagram" title="Click to open zoomable view">'
            f'<pre class="mermaid">{html_mod.escape(src)}</pre>'
            "<figcaption>click diagram to zoom</figcaption></figure>"
        )
        body = body.replace(placeholder, figure, 1)
    return body


def sidebar(active_out: str) -> str:
    items = []
    for _, out, label in PAGES:
        cls = ' class="active"' if out == active_out else ""
        items.append(f'<li{cls}><a href="{out}">{html_mod.escape(label)}</a></li>')
    return "\n".join(items)


def page_title(md_text: str, fallback: str) -> str:
    m = re.search(r"^#\s+(.+)$", md_text, re.M)
    return m.group(1).strip() if m else fallback


def prev_next(idx: int) -> str:
    parts = []
    if idx > 0:
        _, out, label = PAGES[idx - 1]
        parts.append(f'<a class="prev" href="{out}">&larr; {html_mod.escape(label)}</a>')
    else:
        parts.append("<span></span>")
    if idx < len(PAGES) - 1:
        _, out, label = PAGES[idx + 1]
        parts.append(f'<a class="next" href="{out}">{html_mod.escape(label)} &rarr;</a>')
    else:
        parts.append("<span></span>")
    return "".join(parts)


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="assets/walkthrough.css">
</head>
<body>
<div class="layout">
<nav class="sidebar">
<p class="sidebar-title">Walkthrough</p>
<ul>
{sidebar}
</ul>
</nav>
<main class="content">
<article>
{body}
</article>
<footer class="pager">{pager}</footer>
</main>
</div>
<div class="lightbox" id="lightbox" hidden>
  <div class="lightbox-bar">
    <span>scroll to zoom &middot; drag to pan &middot; Esc to close</span>
    <button id="lightbox-close" type="button">&times; close</button>
  </div>
  <div class="lightbox-stage" id="lightbox-stage"></div>
</div>
<script src="assets/mermaid.min.js"></script>
<script src="assets/walkthrough.js"></script>
</body>
</html>
"""


def main() -> None:
    for idx, (md_name, out_name, label) in enumerate(PAGES):
        md_path = HERE / md_name
        md_text = md_path.read_text(encoding="utf-8")
        html_doc = TEMPLATE.format(
            title=html_mod.escape(page_title(md_text, label)),
            sidebar=sidebar(out_name),
            body=convert(md_text),
            pager=prev_next(idx),
        )
        (HERE / out_name).write_text(html_doc, encoding="utf-8")
        print(f"wrote {out_name}")


if __name__ == "__main__":
    main()
