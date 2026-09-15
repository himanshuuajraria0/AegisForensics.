"""Create a raw demo image containing an authentic JPEG evidence payload."""
import os

def create_demo_media():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(tests_dir, exist_ok=True)

    sample_img_path = os.path.join(tests_dir, "sample.jpg")
    if not os.path.exists(sample_img_path):
        from PIL import Image, ImageDraw

        image = Image.new("RGB", (300, 300), color=(15, 23, 42))
        draw = ImageDraw.Draw(image)
        draw.text((40, 140), "AEGIS FORENSICS EVIDENCE", fill=(0, 255, 102))
        image.save(sample_img_path, "JPEG")

    with open(sample_img_path, "rb") as source:
        real_image_bytes = source.read()

    garbage_prefix = b"\x00" * (1024 * 512)
    garbage_suffix = b"\x00" * (1024 * 256)
    raw_disk_data = garbage_prefix + real_image_bytes + garbage_suffix

    disk_path = os.path.join(tests_dir, "disk_dump.raw")
    with open(disk_path, "wb") as target:
        target.write(raw_disk_data)

    print(
        f"[SUCCESS] disk_dump.raw created with authentic JPEG "
        f"({len(real_image_bytes)} bytes) at offset 0x00080000."
    )

if __name__ == "__main__":
    create_demo_media()