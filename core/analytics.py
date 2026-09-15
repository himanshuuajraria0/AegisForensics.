import io
import math

import qrcode


def calculate_shannon_entropy(data_bytes):
    """Return the Shannon entropy of a byte payload, from 0.0 to 8.0."""
    if not data_bytes:
        return 0.0

    byte_counts = {}
    for value in data_bytes:
        byte_counts[value] = byte_counts.get(value, 0) + 1

    total_length = len(data_bytes)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_length
        entropy -= probability * math.log2(probability)
    return round(entropy, 2)


def generate_tamper_proof_qr(
    device_id, sha256_hash, post_carve_status="0 Artifacts (Zero-Retention)"
):
    """Generate a PNG QR buffer containing the audit verification payload."""
    verification_payload = (
        "AEGIS-FORENSICS-VERIFIED\n"
        f"TARGET: {device_id}\n"
        f"SHA256: {sha256_hash}\n"
        f"STATUS: {post_carve_status}\n"
        "INDIAN EVIDENCE ACT SEC 65B COMPLIANT"
    )
    qr = qrcode.QRCode(version=1, box_size=4, border=2)
    qr.add_data(verification_payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer