"""Compatibility entry point for creating the AegisForensics demo image."""

try:
    from .make_disk import create_demo_media
except ImportError:
    from make_disk import create_demo_media


if __name__ == "__main__":
    create_demo_media()