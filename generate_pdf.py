#!/usr/bin/env python3
"""
HELIX Documentation PDF Generator
Converts README.md to a professional PDF with table of contents, headers, and footers
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    Preformatted, PageTemplate, Frame, KeepTogether
)
from reportlab.pdfgen import canvas
from datetime import datetime
import os


class NumberedCanvas(canvas.Canvas):
    """Custom canvas to add page numbers and headers/footers"""
    
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_state = None
        
    def showPage(self):
        self._add_footer_header()
        canvas.Canvas.showPage(self)
        
    def _add_footer_header(self):
        """Add header and footer to each page"""
        self.saveState()
        
        # Header
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#2c3e50"))
        self.drawString(0.5*inch, letter[1] - 0.4*inch, "HELIX - Intelligent Malware Detection")
        
        # Footer with page number
        page_num = self.getPageNumber()
        footer_text = f"Page {page_num}"
        footer_x = letter[0] - 0.8*inch
        self.drawRightString(footer_x, 0.4*inch, footer_text)
        
        # Date
        date_str = datetime.now().strftime("%B %d, %Y")
        self.drawString(0.5*inch, 0.4*inch, date_str)
        
        # Separator line
        self.setStrokeColor(colors.HexColor("#e0e0e0"))
        self.setLineWidth(0.5)
        self.line(0.5*inch, 0.5*inch, letter[0] - 0.5*inch, 0.5*inch)
        self.line(0.5*inch, letter[1] - 0.5*inch, letter[0] - 0.5*inch, letter[1] - 0.5*inch)
        
        self.restoreState()


def create_styled_paragraph(text, style_name, styles_dict):
    """Helper to create styled paragraphs"""
    return Paragraph(text, styles_dict[style_name])


def generate_pdf(output_filename="HELIX_Documentation.pdf"):
    """Generate professional PDF from README content"""
    
    # Create PDF document
    doc = SimpleDocTemplate(
        output_filename,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=1*inch,
        bottomMargin=0.75*inch,
        title="HELIX - Intelligent Malware Detection",
        author="Eyad Arshad"
    )
    
    # Define custom styles
    styles = getSampleStyleSheet()
    
    # Title style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    # Subtitle style
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=colors.HexColor('#555555'),
        spaceAfter=24,
        alignment=TA_CENTER,
        fontName='Helvetica'
    )
    
    # Heading 1 style
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold',
        borderColor=colors.HexColor('#3498db'),
        borderWidth=0,
        borderPadding=6
    )
    
    # Heading 2 style
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    # Body text style
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        alignment=TA_JUSTIFY,
        spaceAfter=10,
        leading=14,
        textColor=colors.HexColor('#333333')
    )
    
    # Code style
    code_style = ParagraphStyle(
        'CustomCode',
        parent=styles['Normal'],
        fontSize=9,
        fontName='Courier',
        textColor=colors.HexColor('#c7254e'),
        backColor=colors.HexColor('#f5f5f5'),
        spaceAfter=8,
        leftIndent=10
    )
    
    # TOC style
    toc_style = ParagraphStyle(
        'TOC',
        parent=styles['Normal'],
        fontSize=10,
        leftIndent=20,
        spaceAfter=6,
        textColor=colors.HexColor('#2c3e50')
    )
    
    # Build the story (content)
    story = []
    
    # --- COVER PAGE ---
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("HELIX", title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("Intelligent Malware Detection<br/>Through Hybrid Static-Behavioral Analysis", subtitle_style))
    story.append(Spacer(1, 0.5*inch))
    
    # Cover description
    cover_text = """
    A next-generation malware detection system combining static PE binary analysis 
    with real-time behavioral sandboxing to identify threats before execution.
    """
    story.append(Paragraph(cover_text.strip(), body_style))
    story.append(Spacer(1, 1*inch))
    
    # Document info
    doc_info = f"""
    <b>Generated:</b> {datetime.now().strftime('%B %d, %Y')}<br/>
    <b>Author:</b> Eyad Arshad<br/>
    <b>Repository:</b> <a href="https://github.com/eyadarshad/HELIX">github.com/eyadarshad/HELIX</a><br/>
    <b>License:</b> Research and Educational Purposes
    """
    story.append(Paragraph(doc_info, body_style))
    story.append(PageBreak())
    
    # --- TABLE OF CONTENTS ---
    story.append(Paragraph("Table of Contents", heading1_style))
    story.append(Spacer(1, 0.2*inch))
    
    toc_items = [
        ("1. Overview", "The Problem"),
        ("2. The Approach", "Dual-Layer Analysis Pipeline"),
        ("3. Architecture", "System Design and Components"),
        ("4. Key Features", "Capabilities and Integrations"),
        ("5. Technology Stack", "Tools and Frameworks"),
        ("6. Installation & Setup", "Getting Started"),
        ("7. Usage Modes", "Running HELIX"),
        ("8. Configuration", "Custom Settings"),
        ("9. Project Structure", "Directory Layout"),
        ("10. How It Works", "Processing Pipeline"),
        ("11. Performance", "Metrics and Results"),
        ("12. License & Author", "Terms and Contact"),
    ]
    
    for toc_num, toc_title in toc_items:
        story.append(Paragraph(f"{toc_num} — {toc_title}", toc_style))
    
    story.append(PageBreak())
    
    # --- CONTENT SECTIONS ---
    
    # 1. OVERVIEW
    story.append(Paragraph("1. Overview", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    overview_text = """
    HELIX is a next-generation malware detection system that combines static PE binary analysis 
    with real-time behavioral sandboxing to identify threats before they execute. Unlike conventional 
    signature-based approaches, HELIX employs hybrid analysis to detect zero-day threats, polymorphic 
    malware, and packed binaries.<br/><br/>
    The system is available as a Windows desktop application with background protection capabilities 
    and integrates with VirusTotal for instant threat intelligence lookup.
    """
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # 2. THE PROBLEM
    story.append(Paragraph("The Problem", heading2_style))
    problem_text = """
    Traditional antivirus software relies on signature matching: a database of known malicious file hashes. 
    This approach fundamentally fails against zero-day threats, polymorphic malware, and packed binaries. 
    HELIX solves this by analyzing file behavior and structure independently, creating resilience against 
    novel malware variants.
    """
    story.append(Paragraph(problem_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # 3. THE APPROACH
    story.append(Paragraph("The Approach", heading2_style))
    approach_intro = """
    HELIX introduces a dual-layer analysis pipeline that fuses two independent intelligence sources 
    into a single verdict:
    """
    story.append(Paragraph(approach_intro, body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Layer 1
    layer1 = """
    <b>Layer 1 — Static PE Analysis (22 features)</b><br/>
    Without executing the file, HELIX dissects the PE header, import table, section table, and binary 
    metadata to extract structural indicators. This includes suspicious API import patterns (process injection, 
    evasion, network), section entropy analysis, and code signing verification.
    """
    story.append(Paragraph(layer1, body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Layer 2
    layer2 = """
    <b>Layer 2 — Behavioral Sandbox (14 features)</b><br/>
    HELIX includes a custom-built x86 instruction emulator that executes binary code in a controlled environment. 
    During execution, it traces register volatility, stack manipulation patterns, memory writes, and evasion 
    techniques (CPUID/RDTSC checks, NOP sleds).
    """
    story.append(Paragraph(layer2, body_style))
    story.append(Spacer(1, 0.1*inch))
    
    # Combined
    combined = """
    <b>Combined Classification (38 features)</b><br/>
    Both layers feed into a calibrated ensemble classifier (VotingClassifier with isotonic calibration) 
    that produces a probability-calibrated threat score between 0.0 (safe) and 1.0 (malicious).
    """
    story.append(Paragraph(combined, body_style))
    story.append(PageBreak())
    
    # 4. ARCHITECTURE
    story.append(Paragraph("Architecture", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    arch_text = """
    The HELIX system architecture consists of multiple integrated components working in parallel 
    to deliver accurate threat detection:
    """
    story.append(Paragraph(arch_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Feature Categories Table
    story.append(Paragraph("Feature Categories", heading2_style))
    
    feature_data = [
        ["Category", "Features", "Signal"],
        ["Import Analysis", "Suspicious API count, injection/evasion/network/persistence imports", "What binary intends to call"],
        ["Section Analysis", "Entropy, section count, writable+executable sections", "Packed or encrypted"],
        ["File Metadata", "Size, header size, import/export count, DLL status, signatures", "Structural anomalies"],
        ["String Analysis", "Suspicious strings, URLs, IP patterns", "Indicators of compromise"],
        ["Behavioral Trace", "Register volatility, stack anomaly, memory density", "Runtime behavior"],
        ["Evasion Detection", "CPUID frequency, RDTSC checks, NOP sled ratio", "Evasion techniques"],
    ]
    
    feature_table = Table(feature_data, colWidths=[1.2*inch, 2.2*inch, 1.8*inch])
    feature_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ddd')),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
    ]))
    
    story.append(feature_table)
    story.append(PageBreak())
    
    # 5. KEY FEATURES
    story.append(Paragraph("Key Features", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    features_list = [
        ("Real-Time Background Protection", 
         "Runs as a Windows system tray service, monitoring Downloads, Desktop, and Temp directories for new executables."),
        ("Distributed Online Learning", 
         "Every HELIX installation connects to a central learning server, enabling continuous model improvement."),
        ("Packer Detection & Decompression", 
         "Automatically detects and decompresses packed binaries (UPX) to analyze the real payload."),
        ("VirusTotal Integration", 
         "Queries VirusTotal API with SHA-256 hash for instant global threat intelligence lookup."),
        ("Authenticode Signature Verification", 
         "Validates Windows Authenticode certificate chains; trusted publishers receive lower threat scores."),
    ]
    
    for feature_name, feature_desc in features_list:
        story.append(Paragraph(f"<b>{feature_name}</b>", heading2_style))
        story.append(Paragraph(feature_desc, body_style))
        story.append(Spacer(1, 0.1*inch))
    
    story.append(PageBreak())
    
    # 6. TECHNOLOGY STACK
    story.append(Paragraph("Technology Stack", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    tech_data = [
        ["Component", "Technology"],
        ["Language", "Python 3.11+"],
        ["Desktop UI", "PyQt6"],
        ["ML Framework", "scikit-learn (CalibratedClassifierCV, VotingClassifier)"],
        ["PE Analysis", "pefile"],
        ["Disassembly", "capstone"],
        ["File Monitoring", "watchdog"],
        ["Threat Intelligence", "VirusTotal API"],
        ["Learning Server", "Flask"],
        ["x86 Emulation", "Custom Python-based instruction emulator"],
    ]
    
    tech_table = Table(tech_data, colWidths=[2*inch, 3.5*inch])
    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
    ]))
    
    story.append(tech_table)
    story.append(PageBreak())
    
    # 7. INSTALLATION
    story.append(Paragraph("Installation & Setup", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    story.append(Paragraph("Clone Repository", heading2_style))
    story.append(Preformatted(
        "git clone https://github.com/eyadarshad/HELIX.git\ncd HELIX\npip install -r requirements.txt",
        code_style
    ))
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Required Dependencies", heading2_style))
    deps_text = """
    pefile • scikit-learn • numpy • PyQt6 • requests • flask • watchdog • capstone • joblib • pandas
    """
    story.append(Paragraph(deps_text, body_style))
    story.append(PageBreak())
    
    # 8. USAGE
    story.append(Paragraph("Usage Modes", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    usage_modes = [
        ("Full UI Mode", "python main.py", 
         "Opens the HELIX desktop application with scanner, dashboard, scan history, and settings."),
        ("Background Guard Mode", "python main.py --tray", 
         "Runs silently in system tray, monitoring for new executables."),
        ("Learning Server", "cd server && python helix_server.py", 
         "Starts the distributed learning server for model improvements."),
    ]
    
    for mode_name, command, description in usage_modes:
        story.append(Paragraph(f"<b>{mode_name}</b>", heading2_style))
        story.append(Preformatted(command, code_style))
        story.append(Paragraph(description, body_style))
        story.append(Spacer(1, 0.15*inch))
    
    story.append(PageBreak())
    
    # 9. CONFIGURATION
    story.append(Paragraph("Configuration", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    story.append(Paragraph("config.json", heading2_style))
    config_code = """{
    "virustotal_api_key": "",
    "server_url": "https://your-server.ngrok-free.dev",
    "server_api_key": ""
}"""
    story.append(Preformatted(config_code, code_style))
    story.append(Spacer(1, 0.15*inch))
    
    config_desc = [
        ("virustotal_api_key", "Free API key from VirusTotal (https://www.virustotal.com)"),
        ("server_url", "Address of HELIX learning server; clear to run offline"),
        ("server_api_key", "HMAC authentication key matching server configuration"),
    ]
    
    for key, desc in config_desc:
        story.append(Paragraph(f"<b>{key}:</b> {desc}", body_style))
    
    story.append(PageBreak())
    
    # 10. HOW IT WORKS
    story.append(Paragraph("How It Works", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    workflow_steps = [
        "File Intake — User drops PE file or background guard detects new download",
        "Parallel Analysis — VirusTotal lookup + local PE feature extraction",
        "Sandbox Execution — Binary disassembled and executed in x86 emulator (50K steps)",
        "Feature Fusion — 22 static + 14 behavioral features = 38-dimensional vector",
        "Classification — Ensemble model produces threat score (0.0–1.0)",
        "User Action — Quarantine, Delete, or Allow (sends correction to server)",
        "Continuous Learning — Corrections pushed to server, model retrains and propagates updates",
    ]
    
    for i, step in enumerate(workflow_steps, 1):
        story.append(Paragraph(f"<b>Step {i}:</b> {step}", body_style))
        story.append(Spacer(1, 0.08*inch))
    
    story.append(PageBreak())
    
    # 11. PERFORMANCE
    story.append(Paragraph("Performance Metrics", heading1_style))
    story.append(Spacer(1, 0.1*inch))
    
    perf_text = """
    Evaluated on a held-out test set of 1,755 labeled PE samples:
    """
    story.append(Paragraph(perf_text, body_style))
    story.append(Spacer(1, 0.1*inch))
    
    perf_data = [
        ["Metric", "Score"],
        ["Accuracy", "99.6%"],
        ["Precision", "99.7%"],
        ["Recall", "99.6%"],
        ["F1 Score", "99.6%"],
    ]
    
    perf_table = Table(perf_data, colWidths=[2*inch, 2*inch])
    perf_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27ae60')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
    ]))
    
    story.append(perf_table)
    story.append(Spacer(1, 0.15*inch))
    
    results_text = """
    The model correctly identifies Windows system binaries (notepad.exe, cmd.exe, explorer.exe, svchost.exe) 
    as safe with threat scores below 0.07, while flagging malicious samples at scores above 0.99.
    """
    story.append(Paragraph(results_text, body_style))
    story.append(PageBreak())
    
    # 12. LICENSE & AUTHOR
    story.append(Paragraph("License & Author", heading1_style))
    story.append(Spacer(1, 0.2*inch))
    
    license_text = """
    <b>License:</b><br/>
    This project is provided for research and educational purposes.
    """
    story.append(Paragraph(license_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    author_text = """
    <b>Author:</b><br/>
    Eyad Arshad<br/>
    GitHub: <a href="https://github.com/eyadarshad">github.com/eyadarshad</a><br/>
    Dataset: <a href="https://www.kaggle.com/datasets/eyadarshad/helix-malware-detection-features">
    Kaggle HELIX Malware Detection Dataset</a>
    """
    story.append(Paragraph(author_text, body_style))
    
    # Build PDF with custom canvas
    doc.build(story, canvasmaker=NumberedCanvas)
    
    return output_filename


if __name__ == "__main__":
    try:
        pdf_file = generate_pdf()
        file_size = os.path.getsize(pdf_file) / (1024 * 1024)  # Convert to MB
        print(f"✅ PDF generated successfully!")
        print(f"📄 File: {pdf_file}")
        print(f"📊 Size: {file_size:.2f} MB")
        print(f"📍 Location: {os.path.abspath(pdf_file)}")
    except Exception as e:
        print(f"❌ Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
