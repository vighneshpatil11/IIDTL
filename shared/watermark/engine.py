"""Forensic Watermark Embedding and Extraction Engine for PDF and Text documents."""

import io
import re
from typing import Optional, Tuple, Dict, Any
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, ArrayObject

from shared.crypto.exceptions import (
    WatermarkingError,
    WatermarkEmbeddingError,
    WatermarkVerificationError,
)
from .zero_width import (
    encode_watermark_zero_width,
    extract_watermark_zero_width,
)


class WatermarkEngine:
    """Unified engine for invisible forensic watermark embedding and extraction with mandatory verification."""

    @staticmethod
    def embed_watermark_in_text(text: str, watermark_id: str) -> str:
        """Embed watermark in plain text by inserting zero-width marker at word boundaries."""
        if not text:
            raise WatermarkEmbeddingError("Cannot embed watermark in empty text document.")
        zw_payload = encode_watermark_zero_width(watermark_id)
        # Insert after the first word or space
        space_idx = text.find(" ")
        if space_idx != -1:
            return text[:space_idx] + zw_payload + text[space_idx:]
        return zw_payload + text

    @staticmethod
    def extract_watermark_from_text(text: str) -> Tuple[Optional[str], float, Dict[str, Any]]:
        """Extract watermark from plain text."""
        if not text:
            return None, 0.0, {
                "method": "zero_width_text",
                "status": "CORRUPT_UNSUPPORTED",
                "classification": "CORRUPT_UNSUPPORTED",
                "confidence": 0.0,
            }
        wm_id, conf = extract_watermark_zero_width(text)
        
        if wm_id and conf >= 0.95:
            classification = "EXACT_MATCH"
        elif wm_id and conf >= 0.7:
            classification = "PARTIAL_MATCH"
        else:
            classification = "NO_MATCH"

        telemetry = {
            "method": "zero_width_text",
            "found": wm_id is not None,
            "confidence": conf,
            "classification": classification,
        }
        return wm_id, conf, telemetry

    @staticmethod
    def embed_watermark_in_pdf(pdf_bytes: bytes, watermark_id: str) -> bytes:
        """Embed multi-layer invisible forensic watermark in PDF bytes.
        
        Layers:
        1. Clean ReportLab vector overlay with invisible micro-forensic text.
        2. Merged content stream with standard ISO-compliant indirect objects.
        3. Structural document catalog metadata containing the forensic payload.

        Raises WatermarkEmbeddingError if the PDF is empty, invalid, or cannot be watermarked.
        """
        if not pdf_bytes:
            raise WatermarkEmbeddingError("PDF bytes are empty.")

        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            if len(reader.pages) == 0:
                raise WatermarkEmbeddingError("PDF contains 0 pages; cannot embed watermark.")
        except Exception as e:
            raise WatermarkEmbeddingError(f"Invalid or corrupted PDF structure: {e}")

        zw_marker = encode_watermark_zero_width(watermark_id)

        try:
            writer = PdfWriter(clone_from=io.BytesIO(pdf_bytes))
            for page in writer.pages:
                try:
                    pw = float(page.mediabox.width)
                    ph = float(page.mediabox.height)
                except Exception:
                    pw, ph = 612.0, 792.0

                # Generate clean invisible overlay with ReportLab
                ov_buf = io.BytesIO()
                oc = canvas.Canvas(ov_buf, pagesize=(pw, ph))
                oc.setFont("Helvetica", 0.1)
                oc.setFillColorRGB(0.99, 0.99, 0.99, alpha=0.01)
                oc.drawString(1, 1, f"DOCFORTRESS-WM:{watermark_id}")
                oc.save()
                ov_buf.seek(0)
                ov_reader = PdfReader(ov_buf)
                page.merge_page(ov_reader.pages[0])

            writer.add_metadata({
                "/ForensicWatermark": watermark_id,
                "/ForensicPayload": zw_marker,
            })

            out_stream = io.BytesIO()
            writer.write(out_stream)
            return out_stream.getvalue()
        except Exception as e:
            raise WatermarkEmbeddingError(f"Failed to embed forensic watermark in PDF: {e}")

    @classmethod
    def extract_watermark_from_pdf(cls, pdf_bytes: bytes) -> Tuple[Optional[str], float, Dict[str, Any]]:
        """Extract invisible forensic watermark from recovered PDF bytes.
        
        Scans all layers:
        - Layer 1: Page extracted text for forensic markers and zero-width characters.
        - Layer 2: Document catalog metadata.
        - Layer 3: Raw content stream tokens.
        
        Returns:
            (watermark_id, confidence_score, telemetry)
        """
        if not pdf_bytes:
            return None, 0.0, {
                "layers_checked": [],
                "hits": [],
                "status": "EMPTY_OR_MISSING_DOCUMENT",
                "classification": "CORRUPT_UNSUPPORTED",
                "error": "Document bytes are empty",
            }

        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            if len(reader.pages) == 0:
                return None, 0.0, {
                    "layers_checked": [],
                    "hits": [],
                    "status": "ZERO_PAGE_DOCUMENT",
                    "classification": "CORRUPT_UNSUPPORTED",
                    "error": "PDF has zero pages",
                }
        except Exception as e:
            return None, 0.0, {
                "layers_checked": [],
                "hits": [],
                "status": "INVALID_OR_CORRUPT_PDF",
                "classification": "CORRUPT_UNSUPPORTED",
                "error": str(e),
            }

        candidates: Dict[str, float] = {}
        layer_hits = []

        # 1. Scan extracted text from each page
        for page_idx, page in enumerate(reader.pages):
            try:
                text = page.extract_text() or ""
                m = re.search(r"DOCFORTRESS-WM:(WM-[A-Za-z0-9_-]+)", text)
                if m:
                    candidates[m.group(1)] = max(candidates.get(m.group(1), 0.0), 1.0)
                    layer_hits.append(f"page_{page_idx}_forensic_marker")

                wm_id, conf = extract_watermark_zero_width(text)
                if wm_id:
                    candidates[wm_id] = max(candidates.get(wm_id, 0.0), conf * 0.95)
                    layer_hits.append(f"page_{page_idx}_text_stream")
            except Exception:
                continue

        # 2. Document metadata
        try:
            meta = reader.metadata or {}
            if "/ForensicWatermark" in meta:
                meta_wm = str(meta["/ForensicWatermark"])
                candidates[meta_wm] = max(candidates.get(meta_wm, 0.0), 1.0)
                layer_hits.append("document_catalog_metadata")
            if "/ForensicPayload" in meta:
                wm_id, conf = extract_watermark_zero_width(str(meta["/ForensicPayload"]))
                if wm_id:
                    candidates[wm_id] = max(candidates.get(wm_id, 0.0), 1.0)
                    layer_hits.append("document_catalog_payload")
        except Exception:
            pass

        # 3. Raw content streams
        try:
            for page_idx, page in enumerate(reader.pages):
                contents = page.get("/Contents")
                raw_streams = []
                if isinstance(contents, ArrayObject):
                    for c in contents:
                        raw_streams.append(c.get_object().get_data())
                elif contents is not None:
                    raw_streams.append(contents.get_object().get_data())

                for s in raw_streams:
                    decoded_text = s.decode("latin1", errors="ignore")
                    m = re.search(r"DOCFORTRESS-WM:(WM-[A-Za-z0-9_-]+)", decoded_text)
                    if m:
                        candidates[m.group(1)] = max(candidates.get(m.group(1), 0.0), 1.0)
                        layer_hits.append(f"page_{page_idx}_raw_content_stream")
                    wm_id, conf = extract_watermark_zero_width(decoded_text)
                    if wm_id:
                        candidates[wm_id] = max(candidates.get(wm_id, 0.0), 0.98)
                        layer_hits.append(f"page_{page_idx}_raw_zero_width")
        except Exception:
            pass

        if not candidates:
            return None, 0.0, {
                "layers_checked": ["extracted_text", "document_metadata", "raw_content_streams"],
                "hits": [],
                "status": "NO_WATERMARK_DETECTED",
                "classification": "NO_MATCH",
            }

        # Select highest confidence candidate
        best_wm_id = max(candidates, key=candidates.get)
        confidence = candidates[best_wm_id]

        if confidence >= 0.95:
            classification = "EXACT_MATCH"
        elif confidence >= 0.70:
            classification = "PARTIAL_MATCH"
        else:
            classification = "NO_MATCH"

        telemetry = {
            "layers_checked": ["extracted_text", "document_metadata", "raw_content_streams"],
            "hits": layer_hits,
            "status": "MATCH_CONFIRMED" if confidence >= 0.8 else "SUSPICIOUS_WEAK_MATCH",
            "classification": classification,
            "candidate_count": len(candidates),
        }

        return best_wm_id, confidence, telemetry

    @classmethod
    def embed_and_verify_pdf(cls, pdf_bytes: bytes, watermark_id: str) -> bytes:
        """Embed watermark and immediately verify that extraction returns the expected watermark ID.
        
        Raises:
            WatermarkEmbeddingError: If embedding fails.
            WatermarkVerificationError: If extraction fails or yields a mismatched watermark ID.
        """
        watermarked = cls.embed_watermark_in_pdf(pdf_bytes, watermark_id)
        extracted_id, conf, telemetry = cls.extract_watermark_from_pdf(watermarked)
        if not extracted_id or extracted_id != watermark_id or conf < 0.8:
            raise WatermarkVerificationError(
                f"Watermark verification failed! Expected '{watermark_id}', extracted '{extracted_id}' (conf={conf:.2f})"
            )
        return watermarked

    @classmethod
    def embed_and_verify_text(cls, text: str, watermark_id: str) -> str:
        """Embed watermark in text and immediately verify that extraction returns the expected watermark ID.
        
        Raises:
            WatermarkEmbeddingError: If embedding fails.
            WatermarkVerificationError: If extraction fails or yields a mismatched watermark ID.
        """
        watermarked = cls.embed_watermark_in_text(text, watermark_id)
        extracted_id, conf, telemetry = cls.extract_watermark_from_text(watermarked)
        if not extracted_id or extracted_id != watermark_id or conf < 0.8:
            raise WatermarkVerificationError(
                f"Watermark verification failed in text! Expected '{watermark_id}', extracted '{extracted_id}' (conf={conf:.2f})"
            )
        return watermarked
