"""PDF scorecard generation for NxtWave AutoEval AI."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, Iterable
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


NAVY = colors.HexColor("#12304A")
TEAL = colors.HexColor("#087E8B")
GREEN = colors.HexColor("#18794E")
RED = colors.HexColor("#B42318")
LIGHT_GREEN = colors.HexColor("#EAF7EF")
LIGHT_RED = colors.HexColor("#FFF1F0")
LIGHT_BLUE = colors.HexColor("#EEF6F8")
TEXT = colors.HexColor("#243746")
MUTED = colors.HexColor("#607887")


def _text(value: Any) -> str:
    return escape(str(value if value is not None else ""))


def _markdown_to_paragraphs(markdown: str, style: ParagraphStyle) -> Iterable[Paragraph]:
    for raw_line in (markdown or "No AI coaching feedback was generated.").splitlines():
        line = raw_line.strip()
        if not line:
            yield Spacer(1, 2 * mm)
            continue
        if line.startswith("### "):
            yield Paragraph(f"<b>{_text(line[4:])}</b>", style)
        elif line.startswith("## "):
            yield Paragraph(f"<b>{_text(line[3:])}</b>", style)
        elif line.startswith("# "):
            yield Paragraph(f"<b>{_text(line[2:])}</b>", style)
        elif line.startswith(('- ', '* ')):
            yield Paragraph(f"&#8226; {_text(line[2:])}", style)
        else:
            yield Paragraph(_text(line), style)


def generate_pdf_scorecard(
    audit_data: Dict[str, Any],
    student_name: str = "NxtWave Student",
) -> bytes:
    """Return a branded PDF scorecard for an AutoEval audit payload."""
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="NxtWave AutoEval AI Scorecard",
        author="NxtWave AutoEval AI",
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "NxtWaveTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=21, leading=25, textColor=NAVY, alignment=TA_CENTER,
        spaceAfter=2 * mm,
    )
    subtitle = ParagraphStyle(
        "NxtWaveSubtitle", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9, leading=12, textColor=MUTED, alignment=TA_CENTER,
    )
    section = ParagraphStyle(
        "NxtWaveSection", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=NAVY, spaceBefore=5 * mm,
        spaceAfter=2 * mm,
    )
    body = ParagraphStyle(
        "NxtWaveBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=TEXT,
    )
    small = ParagraphStyle(
        "NxtWaveSmall", parent=body, fontSize=8, leading=11, textColor=MUTED,
    )
    banner_score = ParagraphStyle(
        "NxtWaveScore", parent=body, fontName="Helvetica-Bold", fontSize=28,
        leading=32, textColor=NAVY, alignment=TA_CENTER,
    )
    banner_status = ParagraphStyle(
        "NxtWaveStatus", parent=body, fontName="Helvetica-Bold", fontSize=11,
        leading=14, textColor=TEAL, alignment=TA_CENTER,
    )

    score = max(0, min(100, int(audit_data.get("compliance_score", 0))))
    status = str(audit_data.get("status", "NEEDS_REVISION"))
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story = [
        Paragraph("NxtWave AutoEval AI", title),
        Paragraph("Automated AI project evaluation and remediation scorecard", subtitle),
        Spacer(1, 4 * mm),
        HRFlowable(width="100%", thickness=1, color=TEAL),
        Spacer(1, 4 * mm),
        Paragraph(f"<b>Student:</b> {_text(student_name)}", body),
        Paragraph(f"<b>Evaluated:</b> {timestamp}", small),
        Spacer(1, 5 * mm),
    ]

    banner = Table(
        [[Paragraph(f"{score}%", banner_score), Paragraph(_text(status), banner_status)]],
        colWidths=[80 * mm, 80 * mm],
        rowHeights=[25 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.8, TEAL),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEAFTER", (0, 0), (0, 0), 0.5, colors.white),
    ]))
    story.extend([banner, Paragraph("Compliance Result", section)])

    implemented = audit_data.get("implemented_rules", []) or []
    story.append(Paragraph("Implemented Rules (Passed)", section))
    if implemented:
        passed_rows = [[Paragraph(f"&#10003;  {_text(rule_id)}", body)] for rule_id in implemented]
        passed_table = Table(passed_rows, colWidths=[160 * mm])
        passed_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREEN),
            ("TEXTCOLOR", (0, 0), (-1, -1), GREEN),
            ("BOX", (0, 0), (-1, -1), 0.5, GREEN),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.white),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(passed_table)
    else:
        story.append(Paragraph("No rules passed in this evaluation.", small))

    violations = audit_data.get("unimplemented_rules", []) or []
    story.append(Paragraph("Unimplemented Rules (Violations)", section))
    if violations:
        violation_rows = []
        for finding in violations:
            location = f"{finding.get('file', 'unknown file')}:{finding.get('line', '?')}"
            detail = (
                f"<b>{_text(finding.get('rule_id', 'unknown-rule'))}</b><br/>"
                f"{_text(location)}<br/>{_text(finding.get('message', ''))}"
            )
            violation_rows.append([Paragraph(f"<font color='#B42318'>&#10007;</font> {detail}", body)])
        violation_table = Table(violation_rows, colWidths=[160 * mm])
        violation_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_RED),
            ("BOX", (0, 0), (-1, -1), 0.5, RED),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(violation_table)
    else:
        story.append(Paragraph("No NxtWave compliance violations were found.", body))

    manual_controls = audit_data.get("manual_review_required", []) or []
    if manual_controls:
        story.append(Paragraph("Controls Requiring Manual Review", section))
        story.append(Paragraph(
            _text(audit_data.get("assessment_note", "These controls are outside static pattern proof.")),
            small,
        ))
        review_rows = [
            [
                Paragraph(f"<b>{_text(control.get('priority', 'high').upper())}</b>", body),
                Paragraph(
                    f"<b>{_text(control.get('category', 'General'))}: "
                    f"{_text(control.get('control', ''))}</b><br/>{_text(control.get('reason', ''))}",
                    body,
                ),
            ]
            for control in manual_controls
        ]
        review_table = Table(review_rows, colWidths=[25 * mm, 135 * mm])
        review_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
            ("BOX", (0, 0), (-1, -1), 0.5, TEAL),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(review_table)

    story.append(Paragraph("AI Coaching Guidance", section))
    coaching = audit_data.get("ai_coaching_feedback", "")
    story.extend(_markdown_to_paragraphs(str(coaching), body))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        f"Total NxtWave violations: {_text(audit_data.get('total_violations', 0))}", small
    ))

    document.build(story)
    return buffer.getvalue()
