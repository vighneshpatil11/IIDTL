"""Forensic Watermark Embedding and Extraction Engine for PDF and Text documents."""

import io
import re
from typing import Optional, Tuple, Dict, Any
from pypdf import PdfReader, PdfWriter
from pypdf.generic import NameObject, create_string_object, ArrayObject, DictionaryObject, DecodedStreamObject

from .zero_width import (
    encode_watermark_zero_width,
    extract_watermark_zero_width,
    ZW_START,
    ZW_END,
)


class WatermarkEngine:
    """Unified engine for invisible forensic watermark embedding and extraction."""

    @staticmethod
    def embed_watermark_in_text(text: str, watermark_id: str) -> str:
        """Embed watermark in plain text by inserting zero-width marker at word boundaries."""
        zw_payload = encode_watermark_zero_width(watermark_id)
        # Insert after the first word or space
        space_idx = text.find(" ")
        if space_idx != -1:
            return text[:space_idx] + zw_payload + text[space_idx:]
        return zw_payload + text

    @staticmethod
    def extract_watermark_from_text(text: str) -> Tuple[Optional[str], float, Dict[str, Any]]:
        """Extract watermark from plain text."""
        wm_id, conf = extract_watermark_zero_width(text)
        telemetry = {
            "method": "zero_width_text",
            "found": wm_id is not None,
            "confidence": conf,
        }
        return wm_id, conf, telemetry

    @staticmethod
    def embed_watermark_in_pdf(pdf_bytes: bytes, watermark_id: str) -> bytes:
        """Embed multi-layer invisible forensic watermark in PDF bytes.
        
        Layers:
        1. Text stream zero-width steganographic injection across pages.
        2. Content stream invisible text operator injection (Tj with rendering mode 3 - invisible text).
        3. Structural forensic marker embedded in page content stream dictionaries.
        """
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
        except Exception as e:
            return None, 0.0, {
                "layers_checked": [],
                "hits": [],
                "status": "INVALID_OR_CORRUPT_PDF",
                "error": str(e),
            }
        writer = PdfWriter()

        zw_marker = encode_watermark_zero_width(watermark_id)
        # Invisible text operator: 3 Tr (render mode invisible) /F1 1 Tf (text) Tj
        # In PDF: `q 3 Tr (payload) Tj Q` ensures it is parsed by PDF text engines but completely invisible visually.
        invisible_stream_content = f"\nq\n3 Tr\n/Helvetica 1 Tf\n({zw_marker}) Tj\nQ\n"

        for page_idx, page in enumerate(reader.pages):
            writer.add_page(page)
            target_page = writer.pages[page_idx]

            # Layer 1 & 2: Append invisible text rendering stream
            try:
                # In pypdf, we can attach or append to the page's contents
                stream_obj = DecodedStreamObject()
                stream_obj.set_data(invisible_stream_content.encode("utf-8"))
                
                contents = target_page.get("/Contents")
                if contents is None:
                    target_page[NameObject("/Contents")] = stream_obj
                elif isinstance(contents, ArrayObject):
                    contents.append(stream_obj)
                else:
                    # Single stream -> convert to array of streams
                    new_array = ArrayObject([contents, stream_obj])
                    target_page[NameObject("/Contents")] = new_array
            except Exception:
                pass

        # Layer 3: Structural piece dictionary (Custom private dictionary, not standard /Info metadata)
        # This attaches a forensic tracking object into the PDF document catalog
        try:
            forensic_marker_dict = DictionaryObject({
                NameObject("/Type"): NameObject("/ForensicWatermark"),
                NameObject("/Payload"): create_string_object(zw_marker),
                NameObject("/Encoding"): create_string_object("ZW-CRC16-V1"),
            })
            writer._root_object[NameObject("/ForensicPieceInfo")] = forensic_marker_dict
        except Exception:
            pass

        out_stream = io.BytesIO()
        writer.write(out_stream)
        return out_stream.getvalue()

    @classmethod
    def extract_watermark_from_pdf(cls, pdf_bytes: bytes) -> Tuple[Optional[str], float, Dict[str, Any]]:
        """Extract invisible forensic watermark from recovered PDF bytes.
        
        Scans all layers:
        - Layer 1: Page extracted text for zero-width characters.
        - Layer 2: Raw content streams for invisible rendering operators (`3 Tr (...) Tj`).
        - Layer 3: Structural forensic dictionary entries.
        
        Returns:
            (watermark_id, confidence_score, telemetry)
        """
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
        except Exception as e:
            return None, 0.0, {
                "layers_checked": [],
                "hits": [],
                "status": "INVALID_OR_CORRUPT_PDF",
                "error": str(e),
            }
        candidates: Dict[str, float] = {}
        layer_hits = []

        # 1. Scan extracted text from each page
        for page_idx, page in enumerate(reader.pages):
            try:
                text = page.extract_text() or ""
                wm_id, conf = extract_watermark_zero_width(text)
                if wm_id:
                    candidates[wm_id] = max(candidates.get(wm_id, 0.0), conf * 0.95)
                    layer_hits.append(f"page_{page_idx}_text_stream")
            except Exception:
                continue

        # 2. Raw content stream regex scan for embedded invisible operators
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
                    wm_id, conf = extract_watermark_zero_width(decoded_text)
                    if wm_id:
                        candidates[wm_id] = max(candidates.get(wm_id, 0.0), 0.98)
                        layer_hits.append(f"page_{page_idx}_raw_content_stream")
        except Exception:
            pass

        # 3. Structural piece info dictionary
        try:
            if "/ForensicPieceInfo" in reader.trailer["/Root"]:
                f_dict = reader.trailer["/Root"]["/ForensicPieceInfo"].get_object()
                payload_str = f_dict.get("/Payload", "")
                wm_id, conf = extract_watermark_zero_width(str(payload_str))
                if wm_id:
                    candidates[wm_id] = max(candidates.get(wm_id, 0.0), 1.0)
                    layer_hits.append("structural_piece_info")
        except Exception:
            pass

        if not candidates:
            return None, 0.0, {
                "layers_checked": ["extracted_text", "raw_content_streams", "piece_info"],
                "hits": [],
                "status": "NO_WATERMARK_DETECTED",
            }

        # Select highest confidence candidate
        best_wm_id = max(candidates, key=candidates.get)
        confidence = candidates[best_wm_id]

        telemetry = {
            "layers_checked": ["extracted_text", "raw_content_streams", "piece_info"],
            "hits": layer_hits,
            "status": "MATCH_CONFIRMED" if confidence >= 0.8 else "SUSPICIOUS_WEAK_MATCH",
            "candidate_count": len(candidates),
        }

        return best_wm_id, confidence, telemetry
