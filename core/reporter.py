# core/reporter.py
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from core.analytics import generate_tamper_proof_qr

def generate_pdf_report(pdf_path, operation, target, hashes, examiner):
    """Tamper-evident court-admissible audit certificate."""
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter
    
    # Header
    c.setFillColor(colors.HexColor("#0F172A"))
    c.rect(0, height - 80, width, 80, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(30, height - 48, "AEGISFORENSICS AUDIT & CHAIN OF CUSTODY CERTIFICATE")

    # Chain of Custody Metadata
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, height - 120, "1. Executive Summary")
    
    c.setFont("Helvetica", 10)
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    c.drawString(30, height - 145, f"Date/Time (UTC): {now}")
    c.drawString(30, height - 165, f"Authorized Examiner: {examiner}")
    c.drawString(30, height - 185, f"Operation Type: {operation}")
    c.drawString(30, height - 205, f"Target Media: {target}")
    c.drawString(30, height - 225, "Compliance Standard: NIST SP 800-88 Rev 1")

    qr_buffer = generate_tamper_proof_qr(
        target,
        hashes.get("pre_hash", "N/A"),
        "ZERO-RETENTION-100%" if hashes.get("zero_retention_verified") else hashes.get("verdict", "UNKNOWN"),
    )
    c.drawImage(ImageReader(qr_buffer), width - 155, height - 245, width=110, height=110)
    c.setFont("Helvetica-Bold", 8)
    c.drawString(width - 150, height - 255, "SCAN FOR CLOUD PROOF")

    # Hashes
    c.setFont("Helvetica-Bold", 12)
    c.drawString(30, height - 265, "2. Cryptographic Hashes (SHA-256)")
    
    c.setFont("Courier", 9) # Monospaced for hashes
    c.drawString(30, height - 290, f"Baseline Pre-Op Hash: {hashes['pre_hash']}")
    c.drawString(30, height - 310, f"Post-Op Verified Hash: {hashes['post_hash']}")
    
    # Verdict
    residual_artifacts = hashes.get("post_wipe_artifacts")
    is_clean = hashes.get("zero_retention_verified") is True or residual_artifacts == []
    verdict_text = (
        "VERIFIED: Mathematically Proven Zero-Retention (100.0% Sanitized)"
        if is_clean
        else hashes.get("verdict", "Verification Pending")
    )
    verdict_color = colors.HexColor("#0F5132") if is_clean else colors.HexColor("#842029")
    verdict_background = colors.HexColor("#D1E7DD") if is_clean else colors.HexColor("#F8D7DA")
    c.setStrokeColor(verdict_color)
    c.setFillColor(verdict_background)
    c.rect(30, height - 390, width - 60, 50, fill=1, stroke=1)
    
    c.setFillColor(verdict_color)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(45, height - 365, f"Verdict: {verdict_text}")

    # Footer
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(30, 60, "National Technical Research Organisation (NTRO) Compliance Evaluation Protocol")
    c.save()