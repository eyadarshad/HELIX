#!/usr/bin/env python3
"""Generate a professional PDF from README.md."""

from __future__ import annotations

import argparse
import html
import os
import re
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer


class NumberedCanvas(canvas.Canvas):
    """Canvas that renders header/footer and page x of y."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_header_footer(page_count)
            super().showPage()
        super().save()

    def _draw_header_footer(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#2c3e50"))
        self.drawString(0.65 * inch, letter[1] - 0.45 * inch, "HELIX Documentation")
        self.drawString(0.65 * inch, 0.4 * inch, datetime.now().strftime("%B %d, %Y"))
        self.drawRightString(
            letter[0] - 0.65 * inch,
            0.4 * inch,
            f"Page {self.getPageNumber()} of {page_count}",
        )
        self.setStrokeColor(colors.HexColor("#d8d8d8"))
        self.setLineWidth(0.5)
        self.line(0.6 * inch, 0.55 * inch, letter[0] - 0.6 * inch, 0.55 * inch)
        self.line(
            0.6 * inch,
            letter[1] - 0.55 * inch,
            letter[0] - 0.6 * inch,
            letter[1] - 0.55 * inch,
        )
        self.restoreState()


def _inline_markdown_to_reportlab(text: str) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" color="blue">\1</a>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", escaped)
    escaped = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", escaped)
    return escaped


def _parse_readme(readme_text: str):
    headings = []
    blocks = []

    lines = readme_text.splitlines()
    paragraph_buffer = []
    in_code = False
    code_lang = ""
    code_buffer = []

    def flush_paragraph():
        if paragraph_buffer:
            blocks.append(("paragraph", " ".join(paragraph_buffer).strip()))
            paragraph_buffer.clear()

    for raw_line in lines:
        line = raw_line.rstrip()

        fence = re.match(r"^```(.*)$", line)
        if fence:
            flush_paragraph()
            if in_code:
                blocks.append(("code", code_lang.strip(), "\n".join(code_buffer)))
                code_buffer = []
                code_lang = ""
                in_code = False
            else:
                in_code = True
                code_lang = fence.group(1)
            continue

        if in_code:
            code_buffer.append(raw_line)
            continue

        heading_match = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading_match:
            flush_paragraph()
            level = len(heading_match.group(1))
            text = heading_match.group(2).strip()
            headings.append((level, text))
            blocks.append(("heading", level, text))
            continue

        if not line.strip():
            flush_paragraph()
            blocks.append(("spacer",))
            continue

        if re.match(r"^\s*[-*+]\s+", line) or re.match(r"^\s*\d+\.\s+", line):
            flush_paragraph()
            item = re.sub(r"^\s*(?:[-*+]|\d+\.)\s+", "", line)
            blocks.append(("list_item", item))
            continue

        if line.strip().startswith("|") and line.strip().endswith("|"):
            flush_paragraph()
            blocks.append(("table_row", line))
            continue

        paragraph_buffer.append(line.strip())

    flush_paragraph()
    if in_code and code_buffer:
        blocks.append(("code", code_lang.strip(), "\n".join(code_buffer)))

    return headings, blocks


def generate_pdf(
    readme_path: str = "README.md",
    output_filename: str = "HELIX_Documentation.pdf",
):
    readme_file = Path(readme_path)
    if not readme_file.exists():
        raise FileNotFoundError(f"README not found: {readme_file}")

    readme_text = readme_file.read_text(encoding="utf-8")
    headings, blocks = _parse_readme(readme_text)

    doc = SimpleDocTemplate(
        output_filename,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.8 * inch,
        title="HELIX Documentation",
        author="Eyad Arshad",
    )

    base_styles = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "Title",
            parent=base_styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=30,
            textColor=colors.HexColor("#102a43"),
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base_styles["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#486581"),
            alignment=TA_CENTER,
            spaceAfter=18,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base_styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#243b53"),
            spaceBefore=10,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base_styles["Heading2"],
            fontSize=13,
            textColor=colors.HexColor("#334e68"),
            spaceBefore=8,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "H3",
            parent=base_styles["Heading3"],
            fontSize=11,
            textColor=colors.HexColor("#486581"),
            spaceBefore=6,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base_styles["BodyText"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#1f2933"),
            alignment=TA_JUSTIFY,
            spaceAfter=7,
        ),
        "toc": ParagraphStyle(
            "TOC",
            parent=base_styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334e68"),
            leftIndent=12,
            spaceAfter=3,
        ),
        "code": ParagraphStyle(
            "Code",
            parent=base_styles["Code"],
            fontName="Courier",
            fontSize=8.7,
            leading=11,
            textColor=colors.HexColor("#102a43"),
            backColor=colors.HexColor("#f5f7fa"),
            leftIndent=6,
            rightIndent=6,
            borderColor=colors.HexColor("#d9e2ec"),
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=4,
            spaceAfter=8,
        ),
        "bullet": ParagraphStyle(
            "Bullet",
            parent=base_styles["BodyText"],
            fontSize=10,
            leading=14,
            leftIndent=16,
            bulletIndent=6,
            textColor=colors.HexColor("#1f2933"),
            spaceAfter=3,
        ),
    }

    title = headings[0][1] if headings else readme_file.stem

    story = [Spacer(1, 1.7 * inch)]
    story.append(Paragraph(_inline_markdown_to_reportlab(title), styles["title"]))
    story.append(
        Paragraph(
            "Professional Documentation Export",
            styles["subtitle"],
        )
    )
    story.append(
        Paragraph(
            f"Source: {html.escape(str(readme_file.resolve()))}<br/>Generated: {datetime.now().strftime('%B %d, %Y')}",
            styles["subtitle"],
        )
    )
    story.append(PageBreak())

    story.append(Paragraph("Table of Contents", styles["h1"]))
    story.append(Spacer(1, 0.12 * inch))
    for level, text in headings:
        if level > 4:
            continue
        indent = max(level - 1, 0) * 12
        toc_line = ParagraphStyle(
            f"TOC_{level}_{len(story)}",
            parent=styles["toc"],
            leftIndent=styles["toc"].leftIndent + indent,
        )
        story.append(Paragraph(_inline_markdown_to_reportlab(text), toc_line))
    story.append(PageBreak())

    for block in blocks:
        kind = block[0]
        if kind == "heading":
            _, level, text = block
            if level <= 1:
                style = styles["h1"]
            elif level == 2:
                style = styles["h2"]
            else:
                style = styles["h3"]
            story.append(Paragraph(_inline_markdown_to_reportlab(text), style))
        elif kind == "paragraph":
            _, text = block
            story.append(Paragraph(_inline_markdown_to_reportlab(text), styles["body"]))
        elif kind == "list_item":
            _, item = block
            story.append(Paragraph(_inline_markdown_to_reportlab(item), styles["bullet"], bulletText="•"))
        elif kind == "code":
            _, lang, code = block
            if lang:
                story.append(Paragraph(f"<b>{html.escape(lang.upper())} code block</b>", styles["h3"]))
            story.append(Preformatted(code, styles["code"]))
        elif kind == "table_row":
            _, row = block
            story.append(Preformatted(row, styles["code"]))
        elif kind == "spacer":
            story.append(Spacer(1, 0.05 * inch))

    doc.build(story, canvasmaker=NumberedCanvas)
    return output_filename


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a professional PDF from README.md")
    parser.add_argument("--readme", default="README.md", help="Path to source markdown file")
    parser.add_argument("--output", default="HELIX_Documentation.pdf", help="Output PDF filename")
    args = parser.parse_args()

    pdf_path = generate_pdf(args.readme, args.output)
    size_mb = os.path.getsize(pdf_path) / (1024 * 1024)
    print("✅ PDF generated successfully")
    print(f"📄 File: {pdf_path}")
    print(f"📍 Location: {os.path.abspath(pdf_path)}")
    print(f"📊 Size: {size_mb:.2f} MB")
