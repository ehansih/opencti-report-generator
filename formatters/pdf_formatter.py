"""
PDF Report Formatter
Generates professional threat intelligence reports as PDFs
"""
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import Flowable


# Brand Colors
COLOR_PRIMARY   = HexColor("#1a1a2e")
COLOR_ACCENT    = HexColor("#7c83fd")
COLOR_RED       = HexColor("#e63946")
COLOR_ORANGE    = HexColor("#f4a261")
COLOR_GREEN     = HexColor("#4ade80")
COLOR_YELLOW    = HexColor("#ffd166")
COLOR_BG        = HexColor("#f8f9fa")
COLOR_BORDER    = HexColor("#dee2e6")

SEVERITY_COLORS = {
    "CRITICAL": HexColor("#e63946"),
    "HIGH":     HexColor("#f4a261"),
    "MEDIUM":   HexColor("#ffd166"),
    "LOW":      HexColor("#4ade80"),
    "INFO":     HexColor("#74b9ff"),
}


class PDFReportFormatter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self.style_title = ParagraphStyle(
            "ReportTitle", fontSize=24, textColor=white,
            fontName="Helvetica-Bold", alignment=TA_LEFT, spaceAfter=4
        )
        self.style_subtitle = ParagraphStyle(
            "ReportSubtitle", fontSize=11, textColor=HexColor("#a5b4fc"),
            fontName="Helvetica", alignment=TA_LEFT
        )
        self.style_h1 = ParagraphStyle(
            "H1", fontSize=14, textColor=COLOR_PRIMARY,
            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
            borderPad=4
        )
        self.style_h2 = ParagraphStyle(
            "H2", fontSize=11, textColor=COLOR_ACCENT,
            fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4
        )
        self.style_body = ParagraphStyle(
            "Body", fontSize=9, textColor=HexColor("#333333"),
            fontName="Helvetica", leading=14, alignment=TA_JUSTIFY,
            spaceAfter=6
        )
        self.style_bullet = ParagraphStyle(
            "Bullet", fontSize=9, textColor=HexColor("#333333"),
            fontName="Helvetica", leading=13, leftIndent=16,
            bulletIndent=6, spaceAfter=3
        )
        self.style_caption = ParagraphStyle(
            "Caption", fontSize=8, textColor=HexColor("#666666"),
            fontName="Helvetica-Oblique", alignment=TA_CENTER
        )
        self.style_footer = ParagraphStyle(
            "Footer", fontSize=7, textColor=HexColor("#999999"),
            fontName="Helvetica", alignment=TA_CENTER
        )

    def _header(self, report_type: str, classification: str = "TLP:WHITE") -> List:
        elements = []

        # Title bar
        title_data = [[
            Paragraph(f"<b>{report_type}</b>", self.style_title),
            Paragraph(f"<b>{classification}</b>",
                ParagraphStyle("TLP", fontSize=10, textColor=white,
                    fontName="Helvetica-Bold", alignment=TA_RIGHT))
        ]]
        title_table = Table(title_data, colWidths=[13*cm, 5*cm])
        title_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), COLOR_PRIMARY),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("PADDING", (0,0), (-1,-1), 12),
            ("ROWHEIGHT", (0,0), (-1,-1), 50),
        ]))
        elements.append(title_table)

        # Meta bar
        now = datetime.utcnow().strftime("%d %B %Y %H:%M UTC")
        meta_data = [[
            Paragraph(f"Generated: {now}", ParagraphStyle("Meta", fontSize=8,
                textColor=HexColor("#666"), fontName="Helvetica")),
            Paragraph("Universal AI Gateway — Threat Intelligence Platform",
                ParagraphStyle("MetaR", fontSize=8, textColor=HexColor("#666"),
                    fontName="Helvetica", alignment=TA_RIGHT))
        ]]
        meta_table = Table(meta_data, colWidths=[9*cm, 9*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), COLOR_BG),
            ("PADDING", (0,0), (-1,-1), 6),
            ("LINEBELOW", (0,0), (-1,-1), 1, COLOR_BORDER),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 0.4*cm))
        return elements

    def _section(self, title: str) -> List:
        elements = [
            HRFlowable(width="100%", thickness=2, color=COLOR_ACCENT,
                       spaceAfter=4, spaceBefore=10),
            Paragraph(title.upper(), self.style_h1),
        ]
        return elements

    def _stat_boxes(self, stats: Dict[str, Any]) -> Table:
        cells = []
        for label, value in stats.items():
            cells.append([
                Paragraph(str(value), ParagraphStyle("StatVal", fontSize=20,
                    fontName="Helvetica-Bold", textColor=COLOR_ACCENT, alignment=TA_CENTER)),
                Paragraph(label, ParagraphStyle("StatLbl", fontSize=8,
                    fontName="Helvetica", textColor=HexColor("#666"), alignment=TA_CENTER))
            ])
        n = len(cells)
        if n == 0:
            return Spacer(1, 0.1*cm)
        data = [cells]
        col_w = 18*cm / n
        t = Table(data, colWidths=[col_w]*n)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), COLOR_BG),
            ("BOX", (0,0), (-1,-1), 1, COLOR_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.5, COLOR_BORDER),
            ("PADDING", (0,0), (-1,-1), 10),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        return t

    def _severity_badge(self, severity: str) -> Paragraph:
        color = SEVERITY_COLORS.get(severity.upper(), HexColor("#999"))
        return Paragraph(
            f'<font color="white"><b> {severity} </b></font>',
            ParagraphStyle("Badge", fontSize=8, fontName="Helvetica-Bold",
                backColor=color, alignment=TA_CENTER)
        )

    def _table(self, headers: List[str], rows: List[List], col_widths: List = None) -> Table:
        header_row = [Paragraph(f"<b>{h}</b>",
            ParagraphStyle("TH", fontSize=8, fontName="Helvetica-Bold",
                textColor=white, alignment=TA_CENTER)) for h in headers]
        data = [header_row]
        for row in rows:
            data.append([Paragraph(str(cell),
                ParagraphStyle("TD", fontSize=8, fontName="Helvetica",
                    textColor=HexColor("#333"))) for cell in row])

        col_w = col_widths or [18*cm / len(headers)] * len(headers)
        t = Table(data, colWidths=col_w)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), COLOR_PRIMARY),
            ("BACKGROUND", (0,1), (-1,-1), white),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, COLOR_BG]),
            ("GRID", (0,0), (-1,-1), 0.5, COLOR_BORDER),
            ("PADDING", (0,0), (-1,-1), 6),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        return t

    def _footer_note(self, classification: str = "TLP:WHITE") -> List:
        return [
            Spacer(1, 0.5*cm),
            HRFlowable(width="100%", thickness=0.5, color=COLOR_BORDER),
            Paragraph(
                f"CLASSIFICATION: {classification} | This report is generated automatically from OpenCTI threat intelligence data. "
                f"Handle according to your organization's information security policy.",
                self.style_footer
            )
        ]

    def generate(self, filename: str, report_type: str, sections: List, classification: str = "TLP:WHITE") -> str:
        filepath = os.path.join(self.output_dir, filename)
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=1.5*cm, leftMargin=1.5*cm,
            topMargin=1.5*cm, bottomMargin=1.5*cm
        )

        elements = []
        elements += self._header(report_type, classification)
        elements += sections
        elements += self._footer_note(classification)

        doc.build(elements)
        return filepath

    # ── Convenience builders ──────────────────────────────────────────────────

    def text(self, content: str) -> Paragraph:
        return Paragraph(content, self.style_body)

    def bullet(self, items: List[str]) -> List:
        return [Paragraph(f"• {item}", self.style_bullet) for item in items]

    def h1(self, title: str) -> List:
        return self._section(title)

    def h2(self, title: str) -> Paragraph:
        return Paragraph(title, self.style_h2)

    def space(self, height: float = 0.3) -> Spacer:
        return Spacer(1, height*cm)

    def page_break(self) -> PageBreak:
        return PageBreak()
