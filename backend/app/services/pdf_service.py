from reportlab.platypus import (
SimpleDocTemplate,
Paragraph,
Spacer,
PageBreak,
Table,
TableStyle,
)

from reportlab.lib.styles import (
getSampleStyleSheet,
ParagraphStyle,
)

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4

class PDFService:

    def generate_report(self,report, output_path):
        doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=28,
            textColor=colors.HexColor("#C1121F"),
            spaceAfter=30,
        )

        section_style = ParagraphStyle(
            "Section",
            parent=styles["Heading1"],
            textColor=colors.HexColor("#C1121F"),
            spaceAfter=12,
        )

        content = []

        # =====================================================
        # COVER PAGE
        # =====================================================

        content.append(
            Paragraph(
                "CloudSecScanner<br/>Security Assessment Report",
                title_style,
            )
        )

        content.append(Spacer(1, 30))

        summary_table = Table(
            [
                ["Target", report.url],
                ["Status", str(report.status)],
                [
                    "Score",
                    str(report.score.total if report.score else "N/A"),
                ],
                [
                    "Grade",
                    str(report.score.grade if report.score else "N/A"),
                ],
                [
                    "Provider",
                    report.cloud.get("provider", "Unknown")
                    if report.cloud
                    else "Unknown",
                ],
            ],
            colWidths=[120, 350],
        )

        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#C1121F")),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )

        content.append(summary_table)

        content.append(PageBreak())

        # =====================================================
        # EXECUTIVE SUMMARY
        # =====================================================

        content.append(
            Paragraph(
                "Executive Summary",
                section_style,
            )
        )

        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        for issue in report.issues:

            sev = str(issue.severity).replace("Severity.", "").upper()

            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            elif sev == "LOW":
                low += 1
            else:
                info += 1

        executive_table = Table(
            [
                ["Metric", "Value"],
                ["Total Findings", str(len(report.issues))],
                ["Critical", str(critical)],
                ["High", str(high)],
                ["Medium", str(medium)],
                ["Low", str(low)],
                ["Info", str(info)],
            ],
            colWidths=[220, 120],
        )

        executive_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#C1121F")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ]
            )
        )

        content.append(executive_table)

        content.append(PageBreak())

        # =====================================================
        # FINDINGS
        # =====================================================

        content.append(
            Paragraph(
                "Security Findings",
                section_style,
            )
        )

        severity_colors = {
            "CRITICAL": "#D00000",
            "HIGH": "#F77F00",
            "MEDIUM": "#FCBF49",
            "LOW": "#4D96FF",
            "INFO": "#6C757D",
        }

        for issue in report.issues:

            sev = str(issue.severity).replace(
                "Severity.",
                "",
            ).upper()

            banner = Table(
                [
                    [
                        f"{sev} - {issue.title}"
                    ]
                ],
                colWidths=[500],
            )

            banner.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            colors.HexColor(
                                severity_colors.get(
                                    sev,
                                    "#888888",
                                )
                            ),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, -1),
                            colors.white,
                        ),
                        (
                            "FONTNAME",
                            (0, 0),
                            (-1, -1),
                            "Helvetica-Bold",
                        ),
                    ]
                )
            )

            content.append(banner)
            content.append(Spacer(1, 8))

            content.append(
                Paragraph(
                    f"<b>Description:</b> {issue.description}",
                    styles["BodyText"],
                )
            )

            content.append(Spacer(1, 4))

            if getattr(issue, "evidence", None):
                content.append(
                    Paragraph(
                        f"<b>Evidence:</b> {issue.evidence}",
                        styles["BodyText"],
                    )
                )

            content.append(Spacer(1, 4))

            recommendation_table = Table(
                [
                    [
                        f"Recommendation: {issue.recommendation}"
                    ]
                ],
                colWidths=[500],
            )

            recommendation_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            colors.HexColor("#E8F5E9"),
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            1,
                            colors.green,
                        ),
                    ]
                )
            )

            content.append(recommendation_table)

            content.append(Spacer(1, 15))

        doc.build(content)

        return output_path

