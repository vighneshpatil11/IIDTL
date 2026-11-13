"""Automated tests for Forensic Watermarking embedding and extraction."""

import io
import pytest
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from shared.watermark.engine import WatermarkEngine
from shared.watermark.zero_width import (
    encode_watermark_zero_width,
    extract_watermark_zero_width,
)


def create_sample_pdf_bytes(text: str = "Confidential Strategic Plan 2027") -> bytes:
    """Generate a clean in-memory PDF using ReportLab."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 700, text)
    c.drawString(100, 650, "Internal organization document. Unauthorized distribution prohibited.")
    c.showPage()
    c.save()
    return buf.getvalue()


class TestWatermarkingEngine:
    """Tests for text and PDF forensic watermarking."""

    def test_zero_width_roundtrip(self):
        wm_id = "WM-A8F31"
        encoded = encode_watermark_zero_width(wm_id)
        extracted, conf = extract_watermark_zero_width(encoded)

        assert extracted == wm_id
        assert conf == 1.0

    def test_text_watermark_embedding_and_extraction(self):
        text = "Confidential report for executive leadership."
        wm_id = "WM-B7D42"

        watermarked_text = WatermarkEngine.embed_watermark_in_text(text, wm_id)
        # Visual check: length increased by invisible characters
        assert len(watermarked_text) > len(text)

        extracted, conf, telemetry = WatermarkEngine.extract_watermark_from_text(watermarked_text)
        assert extracted == wm_id
        assert conf == 1.0
        assert telemetry["found"] is True

    def test_pdf_watermark_embedding_and_extraction(self):
        original_pdf = create_sample_pdf_bytes("Project Neptune Architecture Overview")
        wm_id = "WM-C5E91"

        watermarked_pdf = WatermarkEngine.embed_watermark_in_pdf(original_pdf, wm_id)
        assert len(watermarked_pdf) > 0

        extracted_id, conf, telemetry = WatermarkEngine.extract_watermark_from_pdf(watermarked_pdf)
        assert extracted_id == wm_id
        assert conf >= 0.95
        assert telemetry["status"] == "MATCH_CONFIRMED"

    def test_unwatermarked_pdf_yields_no_match(self):
        original_pdf = create_sample_pdf_bytes("Normal unwatermarked public document")
        extracted_id, conf, telemetry = WatermarkEngine.extract_watermark_from_pdf(original_pdf)

        assert extracted_id is None
        assert conf == 0.0
        assert telemetry["status"] == "NO_WATERMARK_DETECTED"

    def test_corrupted_watermark_reports_no_match(self):
        # Tamper with the zero-width bit payload
        wm_id = "WM-D3F28"
        encoded = encode_watermark_zero_width(wm_id)
        # Corrupt bytes inside
        corrupted = encoded[:5] + "\u200C\u200C" + encoded[10:]
        extracted, conf = extract_watermark_zero_width(corrupted)

        # CRC should fail
        assert extracted is None
