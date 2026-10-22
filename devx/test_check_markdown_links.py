"""Tests for devx/check_markdown_links.py."""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from devx import check_markdown_links as cml


class CheckMarkdownLinksTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _create_file(self, rel_path: str, content: str) -> Path:
        path = self.root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
        return path

    def test_github_slug_basic(self) -> None:
        self.assertEqual(cml.github_slug("Hello World"), "hello-world")
        self.assertEqual(cml.github_slug("Heading with punctuation! (and brackets)"), "heading-with-punctuation-and-brackets")
        self.assertEqual(cml.github_slug("Code `foo_bar` and <em>HTML</em>"), "code-foo_bar-and-html")
        self.assertEqual(cml.github_slug("Slash / separator"), "slash--separator")
        self.assertEqual(cml.github_slug("  Leading and trailing   "), "leading-and-trailing")

    def test_extract_headings_with_duplicates_and_code_blocks(self) -> None:
        content = """
        # Title
        
        ```markdown
        # Not a heading in code
        ```
        
        ## Section A
        
        ### Section A
        
        ## Section B
        
        <a id="custom-anchor"></a>
        """
        headings = cml.extract_headings(textwrap.dedent(content))
        self.assertIn("title", headings)
        self.assertNotIn("not-a-heading-in-code", headings)
        self.assertIn("section-a", headings)
        self.assertIn("section-a-1", headings)
        self.assertIn("section-b", headings)
        self.assertIn("custom-anchor", headings)

    def test_valid_relative_links_and_anchors(self) -> None:
        self._create_file(
            "docs/spec.md",
            """
            # Specification
            
            ## Overview
            Details here.
            
            ## Deep Dive
            More details.
            """,
        )
        readme = self._create_file(
            "README.md",
            """
            # Main Readme
            
            - [Spec Overview](docs/spec.md#overview)
            - [Spec Deep Dive](docs/spec.md#deep-dive)
            - [Self Section](#main-readme)
            - [Non-markdown file](docs/spec.md)
            """,
        )

        cache = {}
        broken = cml.check_markdown_file(readme, headings_cache=cache, repo_root=self.root)
        self.assertEqual(len(broken), 0)

    def test_broken_relative_file_target(self) -> None:
        doc = self._create_file(
            "README.md",
            """
            # Readme
            
            [Broken File](nonexistent/doc.md)
            """,
        )
        cache = {}
        broken = cml.check_markdown_file(doc, headings_cache=cache, repo_root=self.root)
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].line_number, 3)
        self.assertIn("nonexistent/doc.md", broken[0].target)
        self.assertIn("Target file does not exist", broken[0].reason)

    def test_broken_heading_anchor(self) -> None:
        self._create_file(
            "docs/spec.md",
            """
            # Specification
            
            ## Existing Section
            """,
        )
        doc = self._create_file(
            "README.md",
            """
            # Readme
            
            [Broken Anchor](docs/spec.md#missing-section)
            """,
        )
        cache = {}
        broken = cml.check_markdown_file(doc, headings_cache=cache, repo_root=self.root)
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].line_number, 3)
        self.assertIn("docs/spec.md#missing-section", broken[0].target)
        self.assertIn("Anchor '#missing-section' not found", broken[0].reason)

    def test_broken_same_file_anchor(self) -> None:
        doc = self._create_file(
            "README.md",
            """
            # Readme
            
            [Jump](#nonexistent-anchor)
            """,
        )
        cache = {}
        broken = cml.check_markdown_file(doc, headings_cache=cache, repo_root=self.root)
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].line_number, 3)
        self.assertIn("Anchor '#nonexistent-anchor' not found", broken[0].reason)

    def test_ignore_external_links_by_default(self) -> None:
        doc = self._create_file(
            "README.md",
            """
            # External Links
            
            [Google](https://google.com/test)
            [Http](http://example.org)
            [Mail](mailto:dev@example.com)
            """,
        )
        cache = {}
        broken = cml.check_markdown_file(doc, headings_cache=cache, check_external=False, repo_root=self.root)
        self.assertEqual(len(broken), 0)

    @patch("devx.check_markdown_links.check_external_link", return_value=(False, "Connection timeout"))
    def test_check_external_links_when_flag_enabled(self, mock_check_external) -> None:
        doc = self._create_file(
            "README.md",
            """
            # External
            
            [Dead external link](https://broken-domain-test-xyz.org)
            """,
        )
        cache = {}
        broken = cml.check_markdown_file(doc, headings_cache=cache, check_external=True, repo_root=self.root)
        self.assertEqual(len(broken), 1)
        self.assertIn("Connection timeout", broken[0].reason)
        mock_check_external.assert_called_once()

    def test_main_cli_returns_nonzero_on_broken_links(self) -> None:
        self._create_file(
            "README.md",
            """
            # Readme
            
            [Dead](dead.md)
            """,
        )
        exit_code = cml.main(["--root", str(self.root)])
        self.assertEqual(exit_code, 1)

    def test_main_cli_returns_zero_when_clean(self) -> None:
        self._create_file(
            "README.md",
            """
            # Readme
            
            ## Hello
            [To Hello](#hello)
            """,
        )
        exit_code = cml.main(["--root", str(self.root)])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
