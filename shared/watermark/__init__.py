"""Forensic watermarking module."""

from .engine import WatermarkEngine
from .zero_width import (
    encode_watermark_zero_width,
    extract_watermark_zero_width,
)

__all__ = [
    "WatermarkEngine",
    "encode_watermark_zero_width",
    "extract_watermark_zero_width",
]
