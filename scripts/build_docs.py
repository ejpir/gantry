#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown-it-py==4.0.0", "pygments==2.19.2"]
# ///
"""Build the standalone Gantry manual from its Markdown sources.

Run `uv run scripts/build_docs.py`; use --check to detect stale output and
--test to run the generator's tests. No build tools are needed to view the HTML.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import html
import math
import mimetypes
from pathlib import Path
import re
import sys
import unittest
from urllib.parse import quote, unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name
from pygments.lexers.special import TextLexer
from pygments.util import ClassNotFound

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "gantry"
TEMPLATE = ROOT / "scripts" / "docs" / "template.html"
OUTPUT = DOCS / "index.html"
REPOSITORY = "https://github.com/ejpir/gantry"

GROUPS = (
    (
        "Get started",
        (
            ("README.md", "Overview", "book"),
            ("install.md", "Installation", "download"),
            ("get-started.md", "Quickstart", "terminal"),
            ("usage.md", "Everyday usage", "box"),
        ),
    ),
    (
        "Work with Gantry",
        (
            ("images.md", "Images & registries", "layers"),
            ("networking.md", "Networking", "network"),
            ("shares-secrets.md", "Host shares & secrets", "key"),
        ),
    ),
    (
        "Integrations",
        (
            ("coding-agents.md", "Coding agents", "spark"),
            ("ssh-access.md", "SSH & Dev Containers", "code"),
            ("mcp-gateway.md", "MCP gateway", "network"),
            ("manager-api.md", "Manager API", "braces"),
        ),
    ),
    (
        "Reference",
        (
            ("cli-reference.md", "CLI reference", "terminal"),
            ("architecture.md", "Architecture", "layers"),
            ("security.md", "Security model", "shield"),
            ("mcp-worker-confinement.md", "MCP confinement", "shield"),
            ("troubleshooting.md", "Troubleshooting", "help"),
        ),
    ),
)


def icon(name: str, class_name: str = "icon") -> str:
    """Reference an inline SVG symbol, never a network resource."""
    return f'<svg class="{class_name}" aria-hidden="true"><use href="#i-{name}"/></svg>'


def heading_slug(text: str) -> str:
    """Use GitHub-style fragments, with per-document collision suffixes below."""
    text = re.sub(r"[^\w\s-]", "", text.lower(), flags=re.UNICODE)
    return re.sub(r"\s", "-", text) or "section"


def inline_text(token: Token) -> str:
    return "".join(
        " " if child.type in {"softbreak", "hardbreak"} else child.content
        for child in token.children or []
        if child.type not in {"link_open", "link_close", "html_inline"}
    )


@dataclass
class Document:
    path: Path
    label: str
    group: str
    symbol: str
    slug: str = ""
    title: str = ""
    text: str = ""
    tokens: list[Token] = field(default_factory=list)
    headings: list[tuple[str, str, int]] = field(default_factory=list)

    def load(self, parser: MarkdownIt) -> None:
        relative = self.path.relative_to(DOCS)
        self.slug = (
            "overview"
            if relative == Path("README.md")
            else relative.with_suffix("").as_posix().replace("/", "-")
        )
        self.text = self.path.read_text(encoding="utf-8")
        self.tokens = parser.parse(self.text)
        seen: set[str] = set()
        for index, token in enumerate(self.tokens):
            if token.type != "heading_open":
                continue
            title = inline_text(self.tokens[index + 1])
            base = heading_slug(title)
            fragment, suffix = base, 0
            while fragment in seen:
                suffix += 1
                fragment = f"{base}-{suffix}"
            seen.add(fragment)
            token.attrSet("id", f"{self.slug}/{fragment}")
            token.attrSet("tabindex", "-1")
            level = int(token.tag[1:])
            self.headings.append((fragment, title, level))
            if level == 1 and not self.title:
                self.title = title
        if not self.title:
            raise ValueError(f"{self.path}: missing document title")

    @property
    def source_url(self) -> str:
        return f"{REPOSITORY}/blob/main/{quote(self.path.relative_to(ROOT).as_posix())}"


def discover_documents() -> list[Document]:
    documents = [
        Document(DOCS / filename, label, group, symbol)
        for group, entries in GROUPS
        for filename, label, symbol in entries
    ]
    known = {document.path for document in documents}
    extras = sorted(set(DOCS.rglob("*.md")) - known)
    # Numeric ordering keeps release notes newest first (e.g. .20 before .9).
    releases = sorted(
        (path for path in extras if path.parent == DOCS / "releases"),
        key=lambda path: tuple(int(part) for part in re.findall(r"\d+", path.stem)),
        reverse=True,
    )
    documents.extend(
        Document(path, path.stem, "Release notes", "history") for path in releases
    )
    documents.extend(
        Document(
            path, path.stem.replace("-", " ").title(), "More documentation", "book"
        )
        for path in extras
        if path not in releases
    )
    return documents


def rewrite_link(href: str, document: Document, documents: dict[Path, Document]) -> str:
    """Route bundled guides locally; keep other repository references usable."""
    url = urlsplit(href)
    if url.scheme or url.netloc:
        return href
    target = (
        (document.path.parent / unquote(url.path)).resolve()
        if url.path
        else document.path
    )
    destination = documents.get(target)
    if destination:
        fragment = unquote(url.fragment)
        if fragment and fragment not in {item[0] for item in destination.headings}:
            raise ValueError(f"{document.path.name}: missing heading in {href}")
        return f"#{destination.slug}" + (f"/{quote(fragment)}" if fragment else "")
    try:
        relative = target.relative_to(ROOT)
    except ValueError as error:
        raise ValueError(
            f"{document.path.name}: link escapes repository: {href}"
        ) from error
    path = f"{REPOSITORY}/blob/main/{quote(relative.as_posix())}"
    return (
        path
        + (f"?{url.query}" if url.query else "")
        + (f"#{url.fragment}" if url.fragment else "")
    )


def prepare_tokens(document: Document, documents: dict[Path, Document]) -> None:
    """Resolve links, embed local images, and turn GitHub alerts into callouts."""
    for index, token in enumerate(document.tokens):
        for child in token.children or []:
            if child.type == "link_open":
                href = rewrite_link(child.attrGet("href") or "", document, documents)
                child.attrSet("href", href)
                if href.startswith(("https://", "http://")):
                    child.attrSet("target", "_blank")
                    child.attrSet("rel", "noopener noreferrer")
            if child.type == "image":
                source = child.attrGet("src") or ""
                if urlsplit(source).scheme or urlsplit(source).netloc:
                    raise ValueError(
                        f"{document.path}: remote image would break offline viewing"
                    )
                image = (document.path.parent / unquote(source)).resolve()
                if not image.is_relative_to(ROOT):
                    raise ValueError(f"{document.path}: image escapes repository")
                mime = mimetypes.guess_type(image.name)[0] or "application/octet-stream"
                child.attrSet(
                    "src",
                    f"data:{mime};base64,{base64.b64encode(image.read_bytes()).decode()}",
                )
        if token.type != "blockquote_open" or index + 2 >= len(document.tokens):
            continue
        paragraph = document.tokens[index + 2]
        if paragraph.type != "inline":
            continue
        alert = re.match(
            r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\](?:\n|$)", paragraph.content
        )
        if not alert:
            continue
        kind = alert.group(1).lower()
        paragraph.content = paragraph.content[alert.end() :]
        paragraph.children = (
            MarkdownIt("commonmark", {"html": False})
            .enable("strikethrough")
            .parseInline(paragraph.content)[0]
            .children
        )
        end = next(
            candidate
            for candidate in document.tokens[index + 1 :]
            if candidate.type == "blockquote_close" and candidate.level == token.level
        )
        token.type = "html_block"
        token.content = (
            f'<aside class="callout callout-{kind}" aria-label="{kind.title()}">'
            f'<p class="callout-title">{icon("info")} {kind.title()}</p>\n'
        )
        end.type = "html_block"
        end.content = "</aside>\n"


def render_fence(tokens: list[Token], index: int, options: dict, env: dict) -> str:
    token = tokens[index]
    language = token.info.strip().split(maxsplit=1)[0] if token.info.strip() else "text"
    aliases = {"console": "console", "sh": "bash", "shell": "bash", "text": "text"}
    try:
        lexer = get_lexer_by_name(
            aliases.get(language, language), stripnl=False, ensurenl=False
        )
    except ClassNotFound:
        lexer = TextLexer(stripnl=False, ensurenl=False)
    rendered = highlight(token.content, lexer, HtmlFormatter(nowrap=True))
    label = "Mermaid diagram source" if language == "mermaid" else language
    note = ""
    if language == "mermaid":
        # Preserve diagram source rather than requiring an online renderer.
        note = f'<a class="diagram-link" href="{html.escape(env["source_url"])}" target="_blank" rel="noopener noreferrer">View the rendered diagram on GitHub ↗</a>'
    return (
        '<div class="code-block">'
        f'<div class="code-toolbar"><span>{icon("terminal")} {html.escape(label)}</span>'
        '<button type="button" class="copy-code" hidden data-enhance aria-label="Copy example">'
        f'{icon("copy")}<span>Copy</span></button></div>'
        f'<pre tabindex="0" aria-label="{html.escape(label)} example"><code>{rendered}</code></pre>'
        f"{note}</div>\n"
    )


def overview_cards() -> str:
    cards = (
        (
            "install",
            "download",
            "Install Gantry",
            "One binary. Pick your platform.",
            "Start here",
        ),
        (
            "get-started",
            "terminal",
            "Your first sandbox",
            "From an OCI image to a workspace.",
            "Follow the quickstart",
        ),
        (
            "coding-agents",
            "spark",
            "Bring your coding agent",
            "Explicit shares. Your network policy.",
            "Set up a workspace",
        ),
        (
            "architecture",
            "layers",
            "Understand the boundary",
            "Meet the microVM under the hood.",
            "Explore the architecture",
        ),
    )
    return (
        '<div class="guide-grid" aria-label="Recommended guides">'
        + "".join(
            f'<a class="guide-card" href="#{slug}">{icon(symbol)}<strong>{title}</strong>'
            f'<span>{description}</span><span class="guide-action">{action} {icon("arrow")}</span></a>'
            for slug, symbol, title, description, action in cards
        )
        + "</div>"
    )


def render_document(
    document: Document,
    parser: MarkdownIt,
    previous: Document | None,
    following: Document | None,
) -> str:
    tokens = document.tokens
    title_index = next(
        index
        for index, token in enumerate(tokens)
        if token.type == "heading_open" and token.tag == "h1"
    )
    body = tokens[:title_index] + tokens[title_index + 3 :]
    if document.slug == "overview":
        body = list(body)
        insertion = next(
            (index for index, token in enumerate(body) if token.type == "heading_open"),
            len(body),
        )
        card = Token("html_block", "", 0)
        card.content = overview_cards()
        body.insert(insertion, card)
    title = "Welcome to Gantry." if document.slug == "overview" else document.title
    reading_time = max(1, math.ceil(len(document.text.split()) / 220))
    fragment = next(fragment for fragment, _, level in document.headings if level == 1)
    pager = []
    for adjacent, direction in ((previous, "Previous"), (following, "Next")):
        if adjacent:
            pager.append(
                f'<a class="pager-link" href="#{adjacent.slug}"><span>{direction}</span>'
                f'<strong>{html.escape(adjacent.label)} {icon("arrow")}</strong></a>'
            )
        else:
            pager.append('<span class="pager-spacer" aria-hidden="true"></span>')
    current = " is-active" if document.slug == "overview" else ""
    return (
        f'<article class="doc-page{current}" id="{document.slug}" data-label="{html.escape(document.label)}" '
        f'data-group="{html.escape(document.group)}" data-title="{html.escape(title)}">\n'
        '<header class="doc-header">'
        f'<div class="breadcrumbs"><span>{icon("book")} {html.escape(document.group)}</span><span aria-hidden="true">/</span><span>{html.escape(document.label)}</span></div>'
        f'<p class="eyebrow">{"The Gantry manual" if document.slug == "overview" else html.escape(document.group)}</p>'
        f'<h1 id="{document.slug}/{fragment}" tabindex="-1">{html.escape(title)}</h1>'
        f'<div class="page-meta"><span>{reading_time} min read</span><span aria-hidden="true">/</span><span>Markdown, made readable.</span>'
        f'<a href="{document.source_url}" target="_blank" rel="noopener noreferrer">Read source {icon("external")}</a></div></header>\n'
        '<div class="prose">'
        + parser.renderer.render(
            body, parser.options, {"source_url": document.source_url}
        )
        + "</div>"
        '<footer class="doc-footer"><p>Help make these docs better. '
        f'<a href="{document.source_url.replace("/blob/", "/edit/")}" target="_blank" rel="noopener noreferrer">Edit this page on GitHub ↗</a></p>'
        f'<nav class="pager" aria-label="Adjacent guides">{"".join(pager)}</nav></footer></article>\n'
    )


def render_sidebar(documents: list[Document]) -> str:
    result, previous = [], None
    for document in documents:
        if document.group != previous:
            if previous:
                result.append("</div>")
            result.append(
                f'<div class="nav-group"><p class="nav-group-label">{html.escape(document.group)}</p>'
            )
            previous = document.group
        current = ' aria-current="page"' if document.slug == "overview" else ""
        result.append(
            f'<a class="doc-link" href="#{document.slug}" data-page="{document.slug}"{current}>'
            f"{icon(document.symbol)}<span>{html.escape(document.label)}</span></a>"
        )
    return "".join(result) + "</div>"


def build() -> str:
    parser = (
        MarkdownIt("commonmark", {"html": False})
        .enable("table")
        .enable("strikethrough")
    )
    parser.renderer.rules["fence"] = render_fence
    parser.renderer.rules["table_open"] = (
        lambda *_: '<div class="table-scroll" role="region" aria-label="Scrollable table" tabindex="0"><table>\n'
    )
    parser.renderer.rules["table_close"] = lambda *_: "</table></div>\n"
    documents = discover_documents()
    for document in documents:
        document.load(parser)
    lookup = {document.path: document for document in documents}
    for document in documents:
        prepare_tokens(document, lookup)
    content = "".join(
        render_document(
            document,
            parser,
            documents[index - 1] if index else None,
            documents[index + 1] if index + 1 < len(documents) else None,
        )
        for index, document in enumerate(documents)
    )
    replacements = {
        "SIDEBAR": render_sidebar(documents),
        "ARTICLES": content,
        "GUIDE_COUNT": str(len(documents)),
        "CHANGELOG": next(
            (f"#{item.slug}" for item in documents if item.group == "Release notes"),
            "https://github.com/ejpir/gantry/releases",
        ),
    }
    template = TEMPLATE.read_text(encoding="utf-8")
    return re.sub(
        r"\{\{([A-Z_]+)\}\}", lambda match: replacements[match.group(1)], template
    )


def main() -> int:
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument(
        "--check", action="store_true", help="fail if the committed HTML is stale"
    )
    arguments.add_argument(
        "--test", action="store_true", help="run generator unit tests"
    )
    options = arguments.parse_args()
    if options.test:
        sys.dont_write_bytecode = True
        suite = unittest.defaultTestLoader.discover(
            str(Path(__file__).parent), pattern="test_build_docs.py"
        )
        return (
            0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
        )
    output = build()
    if options.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != output:
            print(
                "Docs HTML is stale. Run: uv run scripts/build_docs.py", file=sys.stderr
            )
            return 1
        print("Docs HTML is up to date.")
        return 0
    OUTPUT.write_text(output, encoding="utf-8")
    print(f"Built {OUTPUT.relative_to(ROOT)} ({len(output.encode()):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
