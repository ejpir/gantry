"""Regression tests for the standalone manual generator.

Run with `uv run scripts/build_docs.py --test`.
"""

from html.parser import HTMLParser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urljoin, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token

import build_docs


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = []
        self.anchors = []
        self.resources = []
        self.code_examples = []
        self.in_pre = False
        self.current_code = ""

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "a":
            self.anchors.append(attributes.get("href", ""))
        if tag in {"script", "img", "iframe"} and "src" in attributes:
            self.resources.append(attributes["src"])
        if tag == "link" and attributes.get("rel") == "stylesheet":
            self.resources.append(attributes.get("href", ""))
        if tag == "pre":
            self.in_pre = True
            self.current_code = ""

    def handle_endtag(self, tag):
        if tag == "pre":
            self.in_pre = False
            self.code_examples.append(self.current_code)

    def handle_data(self, data):
        if self.in_pre:
            self.current_code += data


class DocsBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = build_docs.build()
        cls.page = PageParser()
        cls.page.feed(cls.output)
        cls.documents = build_docs.discover_documents()
        cls.parser = MarkdownIt("commonmark", {"html": False}).enable("table")
        for document in cls.documents:
            document.load(cls.parser)

    def test_all_markdown_files_are_included(self):
        self.assertEqual(
            {document.path for document in self.documents},
            set(build_docs.DOCS.rglob("*.md")),
        )
        for document in self.documents:
            self.assertIn(document.slug, self.page.ids)
            for fragment, _, _ in document.headings:
                self.assertIn(f"{document.slug}/{fragment}", self.page.ids)

    def test_ids_are_unique_and_local_links_resolve(self):
        self.assertEqual(len(self.page.ids), len(set(self.page.ids)))
        for href in self.page.anchors:
            if href.startswith("#"):
                self.assertIn(unquote(href[1:]), self.page.ids, href)

    def test_no_external_runtime_resources(self):
        self.assertEqual(self.page.resources, [])
        self.assertNotIn("{{ARTICLES}}", self.output)
        self.assertNotIn("{{SIDEBAR}}", self.output)

    def test_site_links_work_under_github_pages_project_prefix(self):
        showcase = PageParser()
        showcase.feed((build_docs.ROOT / "index.html").read_text(encoding="utf-8"))
        base = "https://ejpir.github.io/gantry/"
        pages = {
            base: showcase,
            base + "index.html": showcase,
            base + "docs/gantry/": self.page,
            base + "docs/gantry/index.html": self.page,
        }
        for source, page in pages.items():
            for href in page.anchors:
                if urlsplit(href).scheme or urlsplit(href).netloc:
                    continue
                destination = urlsplit(urljoin(source, href))
                path = destination._replace(query="", fragment="").geturl()
                self.assertIn(path, pages, f"{source} -> {href}")
                if destination.fragment:
                    self.assertIn(
                        unquote(destination.fragment),
                        pages[path].ids,
                        f"{source} -> {href}",
                    )

    def test_fenced_examples_preserve_source_content(self):
        expected = [
            token.content
            for document in self.documents
            for token in document.tokens
            if token.type == "fence"
        ]
        self.assertEqual(self.page.code_examples, expected)

    def test_nested_release_links_stay_in_the_manual(self):
        documents = {document.path: document for document in self.documents}
        release = documents[build_docs.DOCS / "releases" / "v0.0.20.md"]
        self.assertEqual(
            build_docs.rewrite_link("../images.md", release, documents), "#images"
        )
        self.assertEqual(
            build_docs.rewrite_link(
                "../shares-secrets.md#inject-secrets", release, documents
            ),
            "#shares-secrets/inject-secrets",
        )

    def test_repository_links_remain_usable(self):
        document = self.documents[0]
        self.assertEqual(
            build_docs.rewrite_link("../../SECURITY.md", document, {}),
            "https://github.com/ejpir/gantry/blob/main/SECURITY.md",
        )
        self.assertEqual(
            build_docs.rewrite_link("../editor-integration.md#examples", document, {}),
            "https://github.com/ejpir/gantry/blob/main/docs/editor-integration.md#examples",
        )

    def test_missing_internal_fragment_fails_build(self):
        lookup = {document.path: document for document in self.documents}
        with self.assertRaisesRegex(ValueError, "missing heading"):
            build_docs.rewrite_link(
                "install.md#missing-section", self.documents[0], lookup
            )

    def test_duplicate_headings_have_distinct_fragments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "example.md"
            path.write_text(
                "# Title\n\n## Same\n\n## Same\n\n## Same-1\n", encoding="utf-8"
            )
            with patch.object(build_docs, "DOCS", root):
                document = build_docs.Document(path, "Example", "Tests", "book")
                document.load(self.parser)
            self.assertEqual(
                [item[0] for item in document.headings],
                ["title", "same", "same-1", "same-1-1"],
            )

    def test_callouts_keep_html_escaped_and_rewrite_links(self):
        document = build_docs.Document(
            build_docs.DOCS / "README.md", "Overview", "Get started", "book"
        )
        document.tokens = self.parser.parse(
            "> [!NOTE]\n> A <custom-element> stays text. [Install](install.md).\n"
        )
        lookup = {item.path: item for item in self.documents}
        build_docs.prepare_tokens(document, lookup)
        output = self.parser.renderer.render(document.tokens, self.parser.options, {})
        self.assertIn('class="callout callout-note"', output)
        self.assertIn("&lt;custom-element&gt;", output)
        self.assertNotIn("<custom-element>", output)
        self.assertIn('href="#install"', output)
        self.assertNotIn("[!NOTE]", output)

    def test_unknown_code_language_preserves_text(self):
        token = Token("fence", "code", 0)
        token.info = "unknown-language"
        token.content = '<example> & "quotes"\n'
        output = build_docs.render_fence([token], 0, {}, {})
        page = PageParser()
        page.feed(output)
        self.assertEqual(page.code_examples, [token.content])

    def test_build_is_deterministic(self):
        self.assertEqual(self.output, build_docs.build())


if __name__ == "__main__":
    unittest.main()
