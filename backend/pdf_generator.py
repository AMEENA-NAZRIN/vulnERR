import os
import re
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from bs4 import BeautifulSoup, NavigableString, Tag
from io import BytesIO

REPORT_FOLDER = "reports"
os.makedirs(REPORT_FOLDER, exist_ok=True)


def _escape_xml(text):
    """Escape special XML characters for ReportLab Paragraphs."""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def _parse_suggestions_to_elements(suggestions, styles):
    """
    Parse the HTML suggestions from LLaMA into ReportLab elements.
    Handles h3, h4, p (with inline spans), pre, code, li tags.
    Returns a list of ReportLab flowable elements.
    """
    normal_style = styles["BodyText"]
    subheading_style = styles["Heading3"]

    code_style = ParagraphStyle(
        "CodeStyle",
        parent=normal_style,
        fontName="Courier",
        fontSize=8,
        leading=12,
        textColor=colors.HexColor("#cc0000"),
        backColor=colors.HexColor("#f5f5f5"),
        leftIndent=10,
        spaceAfter=4,
    )

    vuln_title_style = ParagraphStyle(
        "VulnTitle",
        parent=subheading_style,
        textColor=colors.HexColor("#cc0000"),
        spaceAfter=6,
    )

    elements = []
    soup = BeautifulSoup(suggestions, "html.parser")

    # Walk top-level children to preserve document order
    def process_node(node):
        if isinstance(node, NavigableString):
            text = str(node).strip()
            if text:
                elements.append(Paragraph(_escape_xml(text), normal_style))
                elements.append(Spacer(1, 4))
            return

        if not isinstance(node, Tag):
            return

        tag = node.name

        # Vulnerability heading
        if tag == "h3":
            text = node.get_text().strip()
            if text:
                elements.append(Spacer(1, 10))
                elements.append(Paragraph(_escape_xml(text), vuln_title_style))

        # Sub-heading (e.g. "Secure Fix")
        elif tag == "h4":
            text = node.get_text().strip()
            if text:
                elements.append(Spacer(1, 6))
                elements.append(Paragraph(f"<b>{_escape_xml(text)}</b>", normal_style))

        # Paragraph — rebuild inline to catch <span> highlighted code
        elif tag == "p":
            parts = []
            for child in node.children:
                if isinstance(child, NavigableString):
                    chunk = str(child)
                    if chunk.strip():
                        parts.append(_escape_xml(chunk))
                elif isinstance(child, Tag):
                    child_text = child.get_text()
                    if child.name == "span":
                        # Highlighted vulnerable code — show in red bold
                        parts.append(
                            f'<font color="#cc0000"><b>{_escape_xml(child_text)}</b></font>'
                        )
                    elif child.name in ("code", "pre"):
                        parts.append(
                            f'<font name="Courier" size="8">{_escape_xml(child_text)}</font>'
                        )
                    else:
                        parts.append(_escape_xml(child_text))

            combined = "".join(parts).strip()
            if combined:
                elements.append(Paragraph(combined, normal_style))
                elements.append(Spacer(1, 4))

        # Code / pre blocks
        elif tag in ("pre", "code"):
            text = node.get_text().strip()
            if text:
                elements.append(Paragraph(_escape_xml(text), code_style))
                elements.append(Spacer(1, 4))

        # List items
        elif tag == "li":
            text = node.get_text().strip()
            if text:
                elements.append(Paragraph(f"• {_escape_xml(text)}", normal_style))
                elements.append(Spacer(1, 3))

        # Recurse into divs or other containers
        elif tag in ("div", "section", "ul", "ol"):
            for child in node.children:
                process_node(child)

    for child in soup.children:
        process_node(child)

    return elements


def generate_pdf(filename, result, suggestions):
    """Generate a single-file vulnerability report PDF. Returns bytes."""

    try:
        buffer = BytesIO()

        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["BodyText"]

        doc = SimpleDocTemplate(buffer, leftMargin=0.75 * inch, rightMargin=0.75 * inch)
        elements = []

        # Title
        elements.append(Paragraph("VulnERR Security Report", title_style))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(f"<b>File Name:</b> {_escape_xml(filename)}", normal_style))
        elements.append(Spacer(1, 10))

        # Analysis summary
        elements.append(Paragraph("<b>Analysis Result</b>", heading_style))
        elements.append(Spacer(1, 5))

        elements.append(Paragraph(f"Status: {_escape_xml(result.get('status', ''))}", normal_style))
        elements.append(Paragraph(f"Severity: {_escape_xml(result.get('severity', ''))}", normal_style))
        elements.append(Paragraph(f"Message: {_escape_xml(result.get('message', ''))}", normal_style))

        elements.append(Spacer(1, 20))

        # Vulnerability section
        if suggestions and suggestions.strip():
            elements.append(Paragraph("Detected Vulnerabilities &amp; Secure Fix", heading_style))
            elements.append(Spacer(1, 10))

            suggestion_elements = _parse_suggestions_to_elements(suggestions, styles)
            elements.extend(suggestion_elements)

            if not suggestion_elements:
                elements.append(Paragraph("No vulnerability details could be parsed.", normal_style))
        else:
            elements.append(Paragraph(
                "No vulnerabilities detected in this file.",
                normal_style
            ))

        doc.build(elements)
        return buffer.getvalue()

    except Exception as e:
        print("PDF GENERATION ERROR:", str(e))
        raise e


def generate_batch_pdf(batch_data):

    try:
        buffer = BytesIO()

        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["BodyText"]

        doc = SimpleDocTemplate(buffer, leftMargin=0.75 * inch, rightMargin=0.75 * inch)
        elements = []

        # Title
        elements.append(Paragraph("VulnERR Batch Security Report", title_style))
        elements.append(Spacer(1, 20))

        # Batch Info
        elements.append(Paragraph(f"<b>Batch ID:</b> {_escape_xml(str(batch_data['batch_id']))}", normal_style))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("<b>Summary</b>", heading_style))
        elements.append(Paragraph(f"Total Files Scanned: {batch_data['total_files']}", normal_style))
        elements.append(Paragraph(f"Vulnerable Files: {batch_data['vulnerable_count']}", normal_style))
        elements.append(Paragraph(f"Safe Files: {batch_data['safe_count']}", normal_style))

        elements.append(Spacer(1, 20))

        # Summary table
        table_data = [["#", "Filename", "Status", "Severity"]]
        for i, file in enumerate(batch_data["files"], 1):
            table_data.append([
                str(i),
                file["filename"],
                file["status"],
                file["severity"]
            ])

        table = Table(table_data, colWidths=[0.4 * inch, 3 * inch, 1.2 * inch, 1.2 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.cyan),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 30))

        # Detailed results
        elements.append(Paragraph("Detailed Vulnerability Report", heading_style))
        elements.append(Spacer(1, 20))

        for file in batch_data["files"]:
            elements.append(Paragraph(f"<b>File:</b> {_escape_xml(file['filename'])}", normal_style))
            elements.append(Paragraph(f"Status: {_escape_xml(file['status'])}", normal_style))
            elements.append(Paragraph(f"Severity: {_escape_xml(file['severity'])}", normal_style))
            elements.append(Spacer(1, 10))

            if file.get("suggestions") and file["suggestions"].strip():
                elements.append(Paragraph("<b>AI Suggestions:</b>", heading_style))
                elements.append(Spacer(1, 5))

                suggestion_elements = _parse_suggestions_to_elements(file["suggestions"], styles)
                elements.extend(suggestion_elements)

                if not suggestion_elements:
                    elements.append(Paragraph("No details parsed.", normal_style))
            else:
                elements.append(Paragraph("No AI suggestions available.", normal_style))

            elements.append(Spacer(1, 20))

        doc.build(elements)
        return buffer.getvalue()

    except Exception as e:
        print("BATCH PDF GENERATION ERROR:", e)
        raise e
