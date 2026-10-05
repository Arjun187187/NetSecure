import os
from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

REPORT_PDF_DIR = Path("reports/pdf")
REPORT_PDF_DIR.mkdir(parents=True, exist_ok=True)

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute total page count
    and render header/footer on content pages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        if self._pageNumber == 1:
            # Suppress running header & footer on cover page
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#678377"))
        
        # Header line & text
        self.drawString(54, 792, "NETSECURE — DEFENSIVE SECURITY ASSESSMENT REPORT")
        self.setStrokeColor(colors.HexColor("#19372b"))
        self.setLineWidth(0.5)
        self.line(54, 784, 541, 784)

        # Footer line & text
        self.line(54, 48, 541, 48)
        self.setFont("Helvetica", 8)
        self.drawString(54, 34, "CONFIDENTIAL — AUTHORIZED ASSESSMENT")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(541, 34, page_text)
        self.restoreState()


def get_risk_color(risk_str):
    r = (risk_str or "").upper()
    if r == "CRITICAL":
        return colors.HexColor("#ff8e9e"), colors.HexColor("#7a0010")
    elif r == "HIGH":
        return colors.HexColor("#ffb899"), colors.HexColor("#7a2400")
    elif r == "MEDIUM":
        return colors.HexColor("#ffe49a"), colors.HexColor("#614900")
    elif r == "LOW":
        return colors.HexColor("#b8f0ce"), colors.HexColor("#0d4a25")
    else:
        return colors.HexColor("#b9d9ec"), colors.HexColor("#0d3952")


def generate_pdf_report(assessment_data, output_dir=None):
    if output_dir:
        out_path = Path(output_dir)
    else:
        out_path = REPORT_PDF_DIR
    out_path.mkdir(parents=True, exist_ok=True)

    is_discovery = "discovery_id" in assessment_data
    report_id = assessment_data.get("assessment_id") or assessment_data.get("discovery_id") or "NS-UNKNOWN"

    if is_discovery:
        filename = f"NetSecure_ND-{report_id.replace('ND-', '')}.pdf"
    else:
        filename = f"NetSecure_NS-{report_id.replace('NS-', '')}.pdf"

    pdf_filepath = out_path / filename

    # A4 dimensions: 595.27 x 841.89 pt. Available width = 487.27 pt (541 - 54)
    doc = SimpleDocTemplate(
        str(pdf_filepath),
        pagesize=A4,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    style_cover_title = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=30,
        textColor=colors.HexColor("#07110e"),
        spaceAfter=6
    )

    style_cover_subtitle = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#234c3b"),
        spaceAfter=18
    )

    style_h1 = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=17,
        textColor=colors.HexColor("#0d1c17"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    style_h2 = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#19372b"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    style_body = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=6
    )

    style_evidence = ParagraphStyle(
        'Evidence_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#1e293b")
    )

    style_table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.white
    )

    style_table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1f2937")
    )

    story = []

    # =========================================================================
    # 1. COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 40))
    story.append(Paragraph("NETSECURE", style_cover_title))
    story.append(Paragraph("Defensive Network Vulnerability Assessment Report", style_cover_subtitle))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#8fc9ad"), spaceBefore=0, spaceAfter=24))

    meta_table_data = [
        [Paragraph("<b>Assessment Identifier:</b>", style_table_cell), Paragraph(f"<code>{report_id}</code>", style_table_cell)],
        [Paragraph("<b>Target Host / Scope:</b>", style_table_cell), Paragraph(f"<b>{assessment_data.get('target', 'N/A')}</b> ({assessment_data.get('resolved_ip', 'N/A')})", style_table_cell)],
        [Paragraph("<b>Scope Classification:</b>", style_table_cell), Paragraph(f"{assessment_data.get('target_type', 'LOOPBACK')}", style_table_cell)],
        [Paragraph("<b>Assessment Date:</b>", style_table_cell), Paragraph(f"{assessment_data.get('started_at', datetime.now().strftime('%Y-%m-%d'))}", style_table_cell)],
        [Paragraph("<b>Execution Duration:</b>", style_table_cell), Paragraph(f"{assessment_data.get('duration_seconds', 0.0)} seconds", style_table_cell)],
    ]

    if not is_discovery:
        risk_sum = assessment_data.get("risk_summary") or {}
        score = risk_sum.get("risk_score", 100)
        rating = risk_sum.get("risk_rating", "STRONG")
        meta_table_data.append([
            Paragraph("<b>NetSecure Posture Score:</b>", style_table_cell),
            Paragraph(f"<b>{score} / 100</b> ({rating})", style_table_cell)
        ])

    meta_table = Table(meta_table_data, colWidths=[160, 327])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(meta_table)

    story.append(Spacer(1, 140))

    # Cover Page Authorization Notice Box
    auth_notice_data = [[
        Paragraph("<b>AUTHORIZED SECURITY ASSESSMENT REPORT</b><br/><font size=8 color='#475569'>This document contains confidential security assessment results for authorized internal review only. Activities were performed strictly within defined safety boundaries.</font>", style_body)
    ]]
    auth_table = Table(auth_notice_data, colWidths=[487])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94a3b8")),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(auth_table)
    story.append(PageBreak())

    # =========================================================================
    # 2. EXECUTIVE SUMMARY & SECURITY POSTURE
    # =========================================================================
    story.append(Paragraph("1. Executive Summary", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#19372b"), spaceBefore=2, spaceAfter=10))

    target_name = assessment_data.get("target", "target host")
    resolved_ip = assessment_data.get("resolved_ip", target_name)
    findings = assessment_data.get("findings") or []
    risk_summary = assessment_data.get("risk_summary") or {}
    counts = risk_summary.get("counts") or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    score = risk_summary.get("risk_score", 100)
    rating = risk_summary.get("risk_rating", "STRONG")

    exec_text = (
        f"A controlled defensive network security assessment was conducted for target <b>{target_name}</b> ({resolved_ip}) "
        f"on {assessment_data.get('started_at', 'the scheduled assessment date')}. The assessment evaluated network service "
        f"exposure across common TCP management and application ports. Based on empirical scan observations, NetSecure assigned "
        f"a Security Posture Score of <b>{score} / 100</b>, representing a <b>{rating}</b> posture classification."
    )
    story.append(Paragraph(exec_text, style_body))

    # Executive Posture Card Table
    posture_card_data = [
        [
            Paragraph("<b>NetSecure Posture Score</b>", style_table_header),
            Paragraph("<b>Posture Rating</b>", style_table_header),
            Paragraph("<b>Total Findings</b>", style_table_header),
            Paragraph("<b>Critical / High</b>", style_table_header)
        ],
        [
            Paragraph(f"<font size=16 color='#0d1c17'><b>{score} / 100</b></font>", style_table_cell),
            Paragraph(f"<font size=12 color='#0d1c17'><b>{rating}</b></font>", style_table_cell),
            Paragraph(f"<font size=14 color='#0d1c17'><b>{len(findings)}</b></font>", style_table_cell),
            Paragraph(f"<font size=14 color='#b91c1c'><b>{counts.get('CRITICAL',0) + counts.get('HIGH',0)}</b></font>", style_table_cell)
        ]
    ]
    posture_table = Table(posture_card_data, colWidths=[120, 120, 120, 127])
    posture_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0b1814")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(Spacer(1, 6))
    story.append(posture_table)
    story.append(Spacer(1, 12))

    # Severity Distribution Breakdown Table
    dist_data = [
        [
            Paragraph("<b>CRITICAL</b>", style_table_cell),
            Paragraph("<b>HIGH</b>", style_table_cell),
            Paragraph("<b>MEDIUM</b>", style_table_cell),
            Paragraph("<b>LOW</b>", style_table_cell),
            Paragraph("<b>INFO</b>", style_table_cell)
        ],
        [
            Paragraph(f"<b>{counts.get('CRITICAL',0)}</b>", style_table_cell),
            Paragraph(f"<b>{counts.get('HIGH',0)}</b>", style_table_cell),
            Paragraph(f"<b>{counts.get('MEDIUM',0)}</b>", style_table_cell),
            Paragraph(f"<b>{counts.get('LOW',0)}</b>", style_table_cell),
            Paragraph(f"<b>{counts.get('INFO',0)}</b>", style_table_cell)
        ]
    ]
    dist_table = Table(dist_data, colWidths=[97, 97, 97, 97, 99])
    dist_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#ffc4b8")),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor("#ffe89c")),
        ('BACKGROUND', (2,0), (2,0), colors.HexColor("#fef08a")),
        ('BACKGROUND', (3,0), (3,0), colors.HexColor("#b3f5d0")),
        ('BACKGROUND', (4,0), (4,0), colors.HexColor("#bfe3f7")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(dist_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # 3. SCOPE & ASSESSMENT METHODOLOGY
    # =========================================================================
    story.append(Paragraph("2. Assessment Scope & Methodology", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#19372b"), spaceBefore=2, spaceAfter=10))

    scope_data = [
        [Paragraph("<b>Assessment ID:</b>", style_table_cell), Paragraph(f"<code>{report_id}</code>", style_table_cell)],
        [Paragraph("<b>Target Address:</b>", style_table_cell), Paragraph(f"{target_name} ({resolved_ip})", style_table_cell)],
        [Paragraph("<b>Target Scope Type:</b>", style_table_cell), Paragraph(f"{assessment_data.get('target_type', 'LOOPBACK')}", style_table_cell)],
        [Paragraph("<b>Scanned TCP Ports:</b>", style_table_cell), Paragraph(f"{assessment_data.get('ports_scanned', 16)} standard management ports", style_table_cell)],
        [Paragraph("<b>Nmap Service Engine:</b>", style_table_cell), Paragraph(f"Nmap v{assessment_data.get('nmap_version', '7.99.1')} (Available: {assessment_data.get('nmap_available', True)})", style_table_cell)],
        [Paragraph("<b>Assessment Duration:</b>", style_table_cell), Paragraph(f"{assessment_data.get('duration_seconds', 0.0)} seconds", style_table_cell)],
    ]
    scope_table = Table(scope_data, colWidths=[150, 337])
    scope_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ffffff")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(scope_table)

    story.append(Spacer(1, 8))
    methodology_text = (
        "<b>Defensive Testing Methodology:</b> NetSecure employs controlled, authorized assessment methods including "
        "socket connectivity probes and Nmap service version detection. The platform operates strictly in a defensive "
        "capacity and does not perform automated exploitation, password brute-forcing, or denial-of-service tests. "
        "<i>Note: This assessment reflects network exposure observed within the defined testing scope at the time of execution.</i>"
    )
    story.append(Paragraph(methodology_text, style_body))
    story.append(Spacer(1, 14))

    # =========================================================================
    # 4. TECHNICAL EXPOSURE & OPEN PORTS
    # =========================================================================
    story.append(Paragraph("3. Technical Exposure & Open Ports", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#19372b"), spaceBefore=2, spaceAfter=10))

    if len(findings) == 0:
        zero_ports_data = [[
            Paragraph("<b>No Open Ports Identified</b><br/><font size=8.5 color='#475569'>No exposed TCP ports were detected across the evaluated service list during this assessment.</font>", style_body)
        ]]
        zero_ports_table = Table(zero_ports_data, colWidths=[487])
        zero_ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
        ]))
        story.append(zero_ports_table)
    else:
        ports_table_data = [
            [
                Paragraph("<b>Port / Proto</b>", style_table_header),
                Paragraph("<b>State</b>", style_table_header),
                Paragraph("<b>Service</b>", style_table_header),
                Paragraph("<b>Version Information</b>", style_table_header),
                Paragraph("<b>Risk Level</b>", style_table_header)
            ]
        ]
        for f in findings:
            bg_c, text_c = get_risk_color(f.get("risk"))
            risk_p = Paragraph(f"<font color='{text_c.hexval()}'><b>{f.get('risk')}</b></font>", style_table_cell)
            ports_table_data.append([
                Paragraph(f"<b>{f.get('port')}/{f.get('protocol','tcp')}</b>", style_table_cell),
                Paragraph("OPEN", style_table_cell),
                Paragraph(f"<b>{f.get('service','Unknown')}</b>", style_table_cell),
                Paragraph(f"{f.get('version') or '—'}", style_table_cell),
                risk_p
            ])

        ports_table = Table(ports_table_data, colWidths=[85, 55, 95, 172, 80])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0b1814")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(ports_table)

    story.append(Spacer(1, 14))

    # =========================================================================
    # 5. DETAILED SECURITY FINDINGS
    # =========================================================================
    story.append(Paragraph("4. Detailed Security Findings", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#19372b"), spaceBefore=2, spaceAfter=10))

    if len(findings) == 0:
        zero_findings_notice = (
            "<b>No Significant Security Findings Identified</b><br/>"
            "No high-risk exposures or misconfigured services were identified within the tested scope. "
            "<i>Note: This assessment does not guarantee the complete absence of vulnerabilities.</i>"
        )
        zero_f_table = Table([[Paragraph(zero_findings_notice, style_body)]], colWidths=[487])
        zero_f_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
            ('TOPPADDING', (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('LEFTPADDING', (0,0), (-1,-1), 14),
        ]))
        story.append(zero_f_table)
    else:
        for idx, f in enumerate(findings, start=1):
            f_elements = []
            f_id = f.get("finding_id", f"NS-F-{idx:03d}")
            risk = f.get("risk", "INFO")
            conf = f.get("confidence", "HIGH")
            title = f.get("title", f"Port {f.get('port')} Service Exposure")

            bg_c, text_c = get_risk_color(risk)

            f_header = Paragraph(
                f"<b>[{f_id}] {title}</b> — <font color='{text_c.hexval()}'><b>{risk} RISK</b></font> (Confidence: {conf})",
                style_h2
            )
            f_elements.append(f_header)

            f_attr_data = [
                [
                    Paragraph(f"<b>Asset ID:</b> {f.get('asset_id','ASSET-001')}", style_table_cell),
                    Paragraph(f"<b>Target IP:</b> {f.get('target', target_name)}", style_table_cell),
                    Paragraph(f"<b>Port/Proto:</b> {f.get('port')}/{f.get('protocol','tcp')}", style_table_cell),
                    Paragraph(f"<b>Service:</b> {f.get('service','Unknown')}", style_table_cell)
                ]
            ]
            f_attr_table = Table(f_attr_data, colWidths=[120, 120, 110, 137])
            f_attr_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
            ]))
            f_elements.append(f_attr_table)
            f_elements.append(Spacer(1, 4))

            # Observed Evidence Box
            ev_text = f"<b>Observed Technical Evidence:</b><br/>{f.get('evidence','Port open')}"
            ev_table = Table([[Paragraph(ev_text, style_evidence)]], colWidths=[487])
            ev_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#94a3b8")),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
            ]))
            f_elements.append(ev_table)
            f_elements.append(Spacer(1, 4))

            f_elements.append(Paragraph(f"<b>Description:</b> {f.get('description','')}", style_body))
            f_elements.append(Paragraph(f"<b>Security Impact:</b> {f.get('impact','')}", style_body))
            f_elements.append(Paragraph(f"<b>Recommendation:</b> {f.get('recommendation','')}", style_body))
            f_elements.append(Paragraph(f"<b>Remediation Guidance:</b> {f.get('remediation','')}", style_body))
            f_elements.append(Spacer(1, 10))

            story.append(KeepTogether(f_elements))

    # =========================================================================
    # 6. PRIORITIZED REMEDIATION PLAN
    # =========================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("5. Prioritized Remediation & Action Plan", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#19372b"), spaceBefore=2, spaceAfter=10))

    if len(findings) == 0:
        story.append(Paragraph("No immediate security remediations are required for the assessed target.", style_body))
    else:
        rem_items = []
        for idx, f in enumerate(findings, start=1):
            rem_text = f"<b>Step {idx} [{f.get('risk')} Priority]:</b> {f.get('remediation') or f.get('recommendation')}"
            rem_items.append([Paragraph(rem_text, style_body)])

        rem_table = Table(rem_items, colWidths=[487])
        rem_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ffffff")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(rem_table)

    # =========================================================================
    # 7. CONCLUSION & LEGAL DISCLAIMER
    # =========================================================================
    story.append(Spacer(1, 14))
    story.append(Paragraph("6. Assessment Conclusion & Disclaimer", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#19372b"), spaceBefore=2, spaceAfter=10))

    conclusion_text = (
        f"NetSecure evaluated host <b>{target_name}</b> ({resolved_ip}) resulting in a NetSecure Security Posture Score "
        f"of <b>{score} / 100</b> ({rating}). System administrators should review the prioritized remediation plan to reduce "
        f"network exposure and enforce strict access controls on exposed management protocols."
    )
    story.append(Paragraph(conclusion_text, style_body))
    story.append(Spacer(1, 6))

    disclaimer_text = (
        "<b>LEGAL & SAFETY DISCLAIMER:</b><br/>"
        "This report reflects observations from the defined assessment scope and time of testing. "
        "It does not guarantee the absence of vulnerabilities or security weaknesses outside the tested scope. "
        "Assessment activities should only be performed against systems for which the assessor has ownership "
        "or explicit written authorization."
    )
    disc_table = Table([[Paragraph(disclaimer_text, style_body)]], colWidths=[487])
    disc_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94a3b8")),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(disc_table)

    # Build PDF using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)

    return pdf_filepath, filename
