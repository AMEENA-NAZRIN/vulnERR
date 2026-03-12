import os
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from bs4 import BeautifulSoup

REPORT_FOLDER = "reports"
os.makedirs(REPORT_FOLDER, exist_ok=True)


def generate_pdf(filename, result, suggestions):
    try:
        from io import BytesIO  
        
        buffer = BytesIO()  
        
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["BodyText"]

        doc = SimpleDocTemplate(buffer)  # pass buffer
        elements = []
        elements.append(Paragraph("VulnERR Security Report", title_style))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<b>File Name:</b> {filename}", normal_style))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("<b>Analysis Result:</b>", heading_style))
        elements.append(Paragraph(f"Status: {result.get('status','')}", normal_style))
        elements.append(Paragraph(f"Severity: {result.get('severity','')}", normal_style))
        elements.append(Paragraph(f"Message: {result.get('message','')}", normal_style))
        elements.append(Spacer(1, 20))
        if suggestions:
            elements.append(Paragraph("<b>AI Suggestions:</b>", heading_style))
            elements.append(Spacer(1, 10))
            soup = BeautifulSoup(suggestions, "html.parser")
            clean_text = soup.get_text()
            for line in clean_text.split("\n"):
                if line.strip():
                    elements.append(Paragraph(line.strip(), normal_style))
                    elements.append(Spacer(1, 6))

        doc.build(elements)
        pdf_bytes = buffer.getvalue()  # get bytes from buffer
        return pdf_bytes  # always return bytes

    except Exception as e:
        print("PDF GENERATION ERROR:", str(e))
        raise e

