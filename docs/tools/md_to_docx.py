"""Convert the report Markdown into a formatted Word document.

    docs/report_work_details.md ──► docs/Work_Details_Section.docx

Purpose-built for this report rather than a general Markdown converter. It
handles exactly the constructs the report uses -- headings, pipe tables, fenced
code, block quotes, lists and inline emphasis -- and gives the figure/table
placeholders a distinct boxed style so they are impossible to miss when the
author fills them in.

Usage:
    python docs/tools/md_to_docx.py
    python docs/tools/md_to_docx.py --input other.md --output other.docx
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = BASE_DIR / "docs" / "report_work_details.md"
DEFAULT_OUTPUT = BASE_DIR / "docs" / "Work_Details_Section.docx"

ACCENT = RGBColor(0x1F, 0x3B, 0x73)      # heading blue
PLACEHOLDER_TEXT = RGBColor(0x8A, 0x40, 0x00)
CODE_TEXT = RGBColor(0x24, 0x29, 0x2E)

PLACEHOLDER_FILL = "FFF4E5"
CODE_FILL = "F4F5F7"
TABLE_HEADER_FILL = "1F3B73"


# ── Low-level docx helpers ────────────────────────────────────────────────────


def _shade(element, fill: str) -> None:
    """Apply a solid background fill to a paragraph or table cell."""
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    element.append(shd)


def _paragraph_border(paragraph, colour: str = "D9A441", size: int = 6) -> None:
    """Draw a box around a paragraph."""
    p_pr = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(size))
        el.set(qn("w:space"), "6")
        el.set(qn("w:color"), colour)
        borders.append(el)
    p_pr.append(borders)


def _shade_paragraph(paragraph, fill: str) -> None:
    _shade(paragraph._p.get_or_add_pPr(), fill)


def _shade_cell(cell, fill: str) -> None:
    _shade(cell._tc.get_or_add_tcPr(), fill)


def _repeat_header_row(row) -> None:
    """Mark a table row to repeat across page breaks."""
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


# ── Inline formatting ─────────────────────────────────────────────────────────

# Order matters: bold before italic so ** is not consumed as two *.
_INLINE = re.compile(
    r"(\*\*.+?\*\*)"      # bold
    r"|(`[^`]+`)"         # inline code
    r"|(\*[^*]+?\*)"      # italic
)


def add_inline(paragraph, text: str, *, base_size: int = 11, colour=None) -> None:
    """Write text into a paragraph, honouring **bold**, *italic* and `code`."""
    # Markdown links -> just their label; the report has no clickable targets.
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)

    for part in _INLINE.split(text):
        if not part:
            continue
        run = paragraph.add_run()
        run.font.size = Pt(base_size)
        if colour is not None:
            run.font.color.rgb = colour

        if part.startswith("**") and part.endswith("**"):
            run.text = part[2:-2]
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run.text = part[1:-1]
            run.font.name = "Consolas"
            run.font.size = Pt(base_size - 1)
            if colour is None:
                run.font.color.rgb = CODE_TEXT
        elif part.startswith("*") and part.endswith("*"):
            run.text = part[1:-1]
            run.italic = True
        else:
            run.text = part


def strip_inline(text: str) -> str:
    """Plain text with Markdown emphasis markers removed."""
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.replace("**", "").replace("`", "").strip()


# ── Block builders ────────────────────────────────────────────────────────────


def add_placeholder(doc: Document, text: str) -> None:
    """A boxed, shaded marker showing where a figure or table belongs."""
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    para.paragraph_format.space_before = Pt(10)
    para.paragraph_format.space_after = Pt(10)
    para.paragraph_format.left_indent = Inches(0.25)
    para.paragraph_format.right_indent = Inches(0.25)

    run = para.add_run(strip_inline(text))
    run.bold = True
    run.italic = True
    run.font.size = Pt(10.5)
    run.font.color.rgb = PLACEHOLDER_TEXT

    _shade_paragraph(para, PLACEHOLDER_FILL)
    _paragraph_border(para)


def add_code_block(doc: Document, lines: list[str]) -> None:
    para = doc.add_paragraph()
    para.paragraph_format.left_indent = Inches(0.3)
    para.paragraph_format.space_before = Pt(6)
    para.paragraph_format.space_after = Pt(10)
    para.paragraph_format.line_spacing = 1.0

    run = para.add_run("\n".join(lines))
    run.font.name = "Consolas"
    run.font.size = Pt(9)
    run.font.color.rgb = CODE_TEXT
    _shade_paragraph(para, CODE_FILL)


def add_quote(doc: Document, lines: list[str]) -> None:
    text = " ".join(line.strip() for line in lines if line.strip())
    if not text:
        return
    para = doc.add_paragraph()
    para.paragraph_format.left_indent = Inches(0.4)
    para.paragraph_format.space_after = Pt(8)
    add_inline(para, text, base_size=10)
    for run in para.runs:
        run.italic = True


def add_table(doc: Document, rows: list[list[str]]) -> None:
    """Render a pipe table. First row is the header."""
    if not rows:
        return
    columns = max(len(r) for r in rows)
    table = doc.add_table(rows=0, cols=columns)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True

    for index, source_row in enumerate(rows):
        cells = table.add_row().cells
        for col in range(columns):
            value = source_row[col] if col < len(source_row) else ""
            cell = cells[col]
            cell.text = ""
            para = cell.paragraphs[0]
            para.paragraph_format.space_before = Pt(2)
            para.paragraph_format.space_after = Pt(2)

            if index == 0:
                run = para.add_run(strip_inline(value))
                run.bold = True
                run.font.size = Pt(9.5)
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                _shade_cell(cell, TABLE_HEADER_FILL)
            else:
                add_inline(para, value, base_size=9.5)

    if table.rows:
        _repeat_header_row(table.rows[0])

    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def is_separator(line: str) -> bool:
    return bool(re.fullmatch(r"\|?[\s:\-|]+\|?", line.strip())) and "-" in line


# ── Main conversion ───────────────────────────────────────────────────────────


def convert(markdown: str, doc: Document) -> None:
    lines = markdown.split("\n")
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Blank
        if not stripped:
            i += 1
            continue

        # Horizontal rule
        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", stripped):
            para = doc.add_paragraph()
            para.paragraph_format.space_before = Pt(2)
            para.paragraph_format.space_after = Pt(2)
            p_pr = para._p.get_or_add_pPr()
            borders = OxmlElement("w:pBdr")
            bottom = OxmlElement("w:bottom")
            bottom.set(qn("w:val"), "single")
            bottom.set(qn("w:sz"), "6")
            bottom.set(qn("w:space"), "1")
            bottom.set(qn("w:color"), "BBBBBB")
            borders.append(bottom)
            p_pr.append(borders)
            i += 1
            continue

        # Fenced code
        if stripped.startswith("```"):
            i += 1
            block: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            add_code_block(doc, block)
            continue

        # Heading
        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            text = strip_inline(heading.group(2))
            para = doc.add_heading(level=min(level, 4))
            para.paragraph_format.space_before = Pt(14 if level <= 2 else 10)
            para.paragraph_format.space_after = Pt(6)
            run = para.add_run(text)
            run.font.color.rgb = ACCENT
            sizes = {1: 18, 2: 15, 3: 12.5, 4: 11.5}
            run.font.size = Pt(sizes.get(level, 11))
            i += 1
            continue

        # Placeholder (may be wrapped in ** **)
        if re.match(r"^\*{0,2}\[Insert", stripped):
            add_placeholder(doc, stripped)
            i += 1
            continue

        # Block quote
        if stripped.startswith(">"):
            block = []
            while i < n and lines[i].strip().startswith(">"):
                block.append(lines[i].strip().lstrip(">").strip())
                i += 1
            # A quote may contain its own table (the remediation-status blocks).
            if any("|" in b for b in block):
                _convert_quote_with_table(doc, block)
            else:
                add_quote(doc, block)
            continue

        # Table
        if stripped.startswith("|") and i + 1 < n and is_separator(lines[i + 1]):
            rows = [split_row(stripped)]
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            add_table(doc, rows)
            continue

        # Bullet list
        if re.match(r"^[-*+]\s+", stripped):
            para = doc.add_paragraph(style="List Bullet")
            para.paragraph_format.space_after = Pt(3)
            add_inline(para, re.sub(r"^[-*+]\s+", "", stripped))
            i += 1
            continue

        # Numbered list
        if re.match(r"^\d+\.\s+", stripped):
            para = doc.add_paragraph(style="List Number")
            para.paragraph_format.space_after = Pt(3)
            add_inline(para, re.sub(r"^\d+\.\s+", "", stripped))
            i += 1
            continue

        # Paragraph: join continuation lines
        block = [stripped]
        i += 1
        while i < n:
            nxt = lines[i].strip()
            if (not nxt
                    or nxt.startswith(("#", ">", "|", "```", "- ", "* ", "+ "))
                    or re.match(r"^\d+\.\s", nxt)
                    or re.match(r"^\*{0,2}\[Insert", nxt)
                    or re.fullmatch(r"-{3,}", nxt)):
                break
            block.append(nxt)
            i += 1

        para = doc.add_paragraph()
        para.paragraph_format.space_after = Pt(8)
        para.paragraph_format.line_spacing = 1.15
        para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        add_inline(para, " ".join(block))


def _convert_quote_with_table(doc: Document, block: list[str]) -> None:
    """Render a block quote that embeds a pipe table."""
    prose: list[str] = []
    rows: list[list[str]] = []
    for line in block:
        if line.startswith("|"):
            if is_separator(line):
                continue
            rows.append(split_row(line))
        else:
            if rows:
                add_table(doc, rows)
                rows = []
            if line:
                prose.append(line)
            elif prose:
                add_quote(doc, prose)
                prose = []
    if prose:
        add_quote(doc, prose)
    if rows:
        add_table(doc, rows)


def build_document(markdown: str) -> Document:
    doc = Document()

    # Page setup: A4 with 1-inch margins.
    section = doc.sections[0]
    section.page_width = Inches(8.27)
    section.page_height = Inches(11.69)
    for attr in ("top_margin", "bottom_margin", "left_margin", "right_margin"):
        setattr(section, attr, Inches(1))

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)

    convert(markdown, doc)
    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.input.exists():
        raise SystemExit(f"Input not found: {args.input}")

    markdown = args.input.read_text(encoding="utf-8")
    doc = build_document(markdown)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    doc.save(args.output)

    print(f"[DOCX] {args.input.name} -> {args.output}")
    print(f"[DOCX] {len(doc.paragraphs)} paragraphs, {len(doc.tables)} tables")
    return 0


if __name__ == "__main__":
    sys.exit(main())
