# -*- coding: utf-8 -*-
"""
VulnScan - Report Export (HTML -> PDF / Word).

Turns any generated HTML report into a distributable document:
  - PDF:  reportlab (pure Python, registers Chinese font from Windows fonts)
  - DOCX: python-docx
Content is extracted from the HTML (title / paragraphs / tables) and re-laid
out in a clean, document-formatted style. Read-only; no network.

Usage:
  python report_export.py <report.html> [--pdf out.pdf] [--docx out.docx]
  (either --pdf or --docx required; --pdf/--docx default to same basename)
"""

import os
import re
import sys
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"

_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\msyh.ttc",
    r"C:\Windows\Fonts\msyhbd.ttc",
    r"C:\Windows\Fonts\simhei.ttf",
    r"C:\Windows\Fonts\simsun.ttc",
]


def _find_font():
    for p in _FONT_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def extract(html_path):
    """Return (title, paragraphs, tables) from a VulnScan HTML report."""
    with open(html_path, encoding="utf-8") as fp:
        html = fp.read()
    m = re.search(r"<title>(.*?)</title>", html, re.S)
    title = m.group(1).strip() if m else os.path.splitext(os.path.basename(html_path))[0]
    # strip scripts/styles
    body = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S)
    # tables
    tables = []
    for tm in re.finditer(r"<table.*?</table>", body, flags=re.S):
        rows = []
        for trm in re.finditer(r"<tr.*?</tr>", tm.group(0), flags=re.S):
            cells = [re.sub(r"<[^>]+>", "", c).strip()
                     for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", trm.group(0), flags=re.S)]
            if cells:
                rows.append(cells)
        tables.append(rows)
    # paragraphs from remaining text
    text = re.sub(r"<table.*?</table>", " ", body, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[ \t\u3000]+", " ", text)
    paras = [p.strip() for p in re.split(r"\n{1,}", text) if p.strip()]
    return title, paras, tables


# ---------------- PDF ----------------
def export_pdf(html_path, pdf_path):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    title, paras, tables = extract(html_path)
    # register Chinese font
    font_file = _find_font()
    font_name = "Helvetica"
    if font_file:
        try:
            kw = {"subfontIndex": 0} if font_file.endswith(".ttc") else {}
            pdfmetrics.registerFont(TTFont("MSYahei", font_file, **kw))
            font_name = "MSYahei"
        except Exception:
            pass

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontName=font_name,
                        fontSize=18, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontName=font_name,
                        fontSize=13, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("B", parent=styles["Normal"], fontName=font_name,
                          fontSize=10, leading=15)
    cell = ParagraphStyle("C", parent=styles["Normal"], fontName=font_name,
                          fontSize=8.5, leading=11)

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=title, author=PRODUCT)
    story = [Paragraph(title, h1),
             Paragraph(f"由 {PRODUCT} v{VERSION} 导出 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body),
             Spacer(1, 8)]
    for p in paras:
        if len(p) < 200:
            story.append(Paragraph(p, body))
    for ti, tbl in enumerate(tables, 1):
        if not tbl:
            continue
        story.append(Paragraph(f"数据表 {ti}", h2))
        data = [[Paragraph(str(c), cell) for c in row] for row in tbl]
        avail = doc.width
        ncol = max((len(r) for r in tbl), default=1)
        colw = [avail / ncol] * ncol
        t = Table(data, colWidths=colw, repeatRows=1)
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9dee7")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f3f8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))
    story.append(Paragraph("免责声明：本报告由 VulnScan 生成，仅用于你有权测试的资产；"
                           "未发送任何攻击载荷，未授权使用后果自负。", body))
    doc.build(story)
    return pdf_path


# ---------------- DOCX ----------------
def export_docx(html_path, docx_path):
    from docx import Document
    from docx.shared import Pt, RGBColor

    title, paras, tables = extract(html_path)
    doc = Document()
    doc.core_properties.title = title
    doc.core_properties.author = PRODUCT
    h = doc.add_heading(title, level=0)
    p = doc.add_paragraph()
    r = p.add_run(f"由 {PRODUCT} v{VERSION} 导出 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    r.font.size = Pt(9)
    r.font.color.rgb = RGBColor(0x8a, 0x93, 0xa6)
    for para in paras:
        if len(para) < 200 and not para.startswith("<!") and not para.startswith("http"):
            doc.add_paragraph(para)
    for ti, tbl in enumerate(tables, 1):
        if not tbl:
            continue
        doc.add_heading(f"数据表 {ti}", level=1)
        ncol = max((len(rw) for rw in tbl), default=1)
        table = doc.add_table(rows=len(tbl), cols=ncol)
        table.style = "Light Grid Accent 1"
        for ri, row in enumerate(tbl):
            for ci in range(ncol):
                val = row[ci] if ci < len(row) else ""
                table.cell(ri, ci).text = str(val)[:8000]
    doc.add_paragraph("免责声明：本报告由 VulnScan 生成，仅用于你有权测试的资产；"
                      "未发送任何攻击载荷，未授权使用后果自负。")
    doc.save(docx_path)
    return docx_path


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    html_path = args[0]
    if not os.path.isfile(html_path):
        print(f"[错误] 报告文件不存在: {html_path}")
        return 1
    base = os.path.splitext(html_path)[0]
    pdf_out = None
    docx_out = None
    if "--pdf" in args:
        pdf_out = args[args.index("--pdf") + 1]
    elif "--docx" not in args:
        pdf_out = base + ".pdf"
    if "--docx" in args:
        docx_out = args[args.index("--docx") + 1]
    elif "--pdf" not in args:
        docx_out = base + ".docx"
    if pdf_out:
        export_pdf(html_path, pdf_out)
        print(f"PDF 已导出: {pdf_out}")
    if docx_out:
        export_docx(html_path, docx_out)
        print(f"Word 已导出: {docx_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
