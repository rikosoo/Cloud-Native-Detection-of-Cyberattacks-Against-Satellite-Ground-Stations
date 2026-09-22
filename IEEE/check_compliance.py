#!/usr/bin/env python3
"""Check the submission against the journal's formatting rules.

Automates the checks that get a manuscript desk-rejected before review:

  * page count within the submission limit, and within the no-fee ceiling
  * abstract within the word limit, one paragraph, no citations, no equations
  * every abbreviation in the abstract defined on first use
  * no author biographies
  * double-column 10pt journal class

Run after building:  python IEEE/check_compliance.py
Exits non-zero if any hard rule fails, so CI can gate on it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# --- the rules ------------------------------------------------------------- #
PAGE_LIMIT_SUBMISSION = 10  # over this, rejected without review
PAGE_LIMIT_FREE = 8  # over this, per-page charges apply
ABSTRACT_WORD_LIMIT = 250

#: Abbreviations that need no definition: standard English or universally known.
ABBREVIATION_ALLOWLIST = {
    "AI",
    "US",
    "UTC",
    "IEEE",
}


def macros() -> dict[str, str]:
    path = HERE / "data" / "macros.tex"
    if not path.exists():
        return {}
    return dict(re.findall(r"\\newcommand\{\\(exp\w+)\}\{(.*?)\}\s*$", path.read_text(), re.M))


def expand(text: str, values: dict[str, str]) -> str:
    def repl(match: re.Match) -> str:
        return values.get(match.group(1), "0")

    return re.sub(r"\\(exp\w+)(?:\{\})?", repl, text)


def abstract_of(source: str) -> str:
    match = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", source, re.S)
    if not match:
        raise SystemExit("no abstract found")
    return match.group(1).strip()


def word_count(text: str) -> int:
    text = re.sub(r"\\[a-zA-Z]+\*?", " ", text)  # drop commands
    text = re.sub(r"[{}$\\]", " ", text)
    return len([w for w in text.split() if any(c.isalnum() for c in w)])


def page_count(pdf: Path) -> int | None:
    if not pdf.exists() or not shutil.which("pdfinfo"):
        return None
    out = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True, check=True).stdout
    match = re.search(r"^Pages:\s+(\d+)", out, re.M)
    return int(match.group(1)) if match else None


def undefined_abbreviations(abstract: str) -> list[str]:
    """Acronyms of 2+ capitals that never appear beside a parenthesised gloss."""
    plain = re.sub(r"\\[a-zA-Z]+\*?", " ", abstract)
    found = set(re.findall(r"\b([A-Z]{2,})\b", plain))
    defined = set(re.findall(r"\(([A-Z]{2,})\)", plain))
    return sorted(found - defined - ABBREVIATION_ALLOWLIST)


def main() -> int:
    source = (HERE / "main.tex").read_text()
    values = macros()
    abstract = abstract_of(source)
    expanded = expand(abstract, values)

    checks: list[tuple[str, bool, str]] = []

    # Page limits ----------------------------------------------------------
    pages = page_count(HERE / "main.pdf")
    if pages is None:
        checks.append(("page count", True, "main.pdf or pdfinfo missing - build first (skipped)"))
    else:
        checks.append(
            (
                "page limit (submission)",
                pages <= PAGE_LIMIT_SUBMISSION,
                f"{pages} pages, limit {PAGE_LIMIT_SUBMISSION}",
            )
        )
        over = max(0, pages - PAGE_LIMIT_FREE)
        checks.append(
            (
                "page limit (no fee)",
                over == 0,
                f"{pages} pages, {PAGE_LIMIT_FREE} free"
                + (f", {over} chargeable" if over else ""),
            )
        )

    # Abstract -------------------------------------------------------------
    words = word_count(expanded)
    checks.append(
        ("abstract length", words <= ABSTRACT_WORD_LIMIT, f"{words} words, limit {ABSTRACT_WORD_LIMIT}")
    )
    checks.append(
        (
            "abstract is one paragraph",
            "\n\n" not in abstract and r"\par" not in abstract,
            "no blank line or \\par",
        )
    )
    checks.append(
        ("abstract has no citations", r"\cite" not in abstract, "no \\cite")
    )
    equation_markers = abstract.count("$") + len(
        re.findall(r"\\begin\{(equation|align|math)", abstract)
    )
    checks.append(
        ("abstract has no equations", equation_markers == 0, f"{equation_markers} math markers")
    )
    undefined = undefined_abbreviations(abstract)
    checks.append(
        (
            "abstract abbreviations defined",
            not undefined,
            "all defined" if not undefined else f"undefined: {', '.join(undefined)}",
        )
    )

    # Structure ------------------------------------------------------------
    checks.append(
        (
            "no author biographies",
            "IEEEbiography" not in source,
            "no \\begin{IEEEbiography}",
        )
    )
    declared = re.search(r"\\documentclass\[([^\]]*)\]", source)
    options = declared.group(1) if declared else ""
    checks.append(
        (
            "double column, 10pt journal",
            "10pt" in options and "journal" in options,
            f"documentclass[{options}]",
        )
    )
    checks.append(
        (
            "generative AI use declared",
            "generative AI" in source or "artificial intelligence" in source,
            "declaration present",
        )
    )

    width = max(len(name) for name, _, _ in checks)
    failures = 0
    for name, ok, detail in checks:
        if not ok:
            failures += 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {name.ljust(width)}  {detail}")

    print()
    if failures:
        print(f"{failures} rule(s) failed")
    else:
        print("all rules satisfied")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
