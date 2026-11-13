"""Zero-width Unicode steganography engine for text and document streams."""

import binascii
from typing import Optional, Tuple


ZW_ZERO = "\u200C"   # Zero-width non-joiner -> bit 0
ZW_ONE = "\u200D"    # Zero-width joiner -> bit 1
ZW_START = "\u200B"  # Zero-width space -> frame sync start
ZW_END = "\uFEFF"    # Zero-width non-breaking space (BOM) -> frame sync end


def _string_to_bits(s: str) -> str:
    """Convert ASCII string to bit string with a 16-bit CRC checksum for error detection."""
    data_bytes = s.encode("utf-8")
    crc = binascii.crc32(data_bytes) & 0xFFFF
    full_payload = data_bytes + crc.to_bytes(2, "big")
    return "".join(f"{byte:08b}" for byte in full_payload)


def _bits_to_string(bits: str) -> Optional[str]:
    """Parse bit string, verify 16-bit CRC checksum, and decode UTF-8 string."""
    if len(bits) % 8 != 0 or len(bits) < 24:  # At least 1 char + 2-byte CRC
        return None

    byte_list = []
    for i in range(0, len(bits), 8):
        byte_list.append(int(bits[i:i+8], 2))

    payload_bytes = bytes(byte_list)
    data_bytes = payload_bytes[:-2]
    expected_crc = int.from_bytes(payload_bytes[-2:], "big")

    computed_crc = binascii.crc32(data_bytes) & 0xFFFF
    if computed_crc != expected_crc:
        return None

    try:
        return data_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def encode_watermark_zero_width(watermark_id: str) -> str:
    """Encode watermark ID into invisible zero-width Unicode sequence with framing and CRC."""
    bits = _string_to_bits(watermark_id)
    zw_bits = "".join(ZW_ONE if b == "1" else ZW_ZERO for b in bits)
    return f"{ZW_START}{zw_bits}{ZW_END}"


def extract_watermark_zero_width(text: str) -> Tuple[Optional[str], float]:
    """Extract and verify watermark from text containing zero-width markers.
    
    Returns:
        (watermark_id, confidence_score)
        where confidence is 1.0 for CRC verified match, or lower if corrupted.
    """
    if not text:
        return None, 0.0

    start_idx = text.find(ZW_START)
    if start_idx == -1:
        return None, 0.0

    end_idx = text.find(ZW_END, start_idx)
    if end_idx == -1:
        return None, 0.0

    raw_segment = text[start_idx + len(ZW_START):end_idx]
    bit_chars = []
    for ch in raw_segment:
        if ch == ZW_ZERO:
            bit_chars.append("0")
        elif ch == ZW_ONE:
            bit_chars.append("1")

    bit_string = "".join(bit_chars)
    extracted = _bits_to_string(bit_string)
    if extracted:
        return extracted, 1.0

    # If CRC failed but bits look partially structured
    if len(bit_string) >= 24:
        return None, 0.35

    return None, 0.0
