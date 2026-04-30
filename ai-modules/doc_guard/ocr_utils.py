"""
ocr_utils.py
Text extraction from PDF and image files.

Dependencies:
    pip install pdfminer.six pytesseract pillow

Tesseract binary path is auto-detected for macOS, Linux, and Windows.
Override with env var: TESSERACT_CMD=/path/to/tesseract
"""

import io
import os
import re
import shutil

# ── Tesseract binary path ──────────────────────────────────────────────────────
# Auto-detect: env var → macOS Homebrew → Linux default → Windows fallback
def _find_tesseract() -> str:
    env = os.getenv("TESSERACT_CMD")
    if env:
        return env
    # macOS Homebrew (arm64 and x86_64)
    for p in ["/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract"]:
        if os.path.isfile(p):
            return p
    # Linux default
    if os.path.isfile("/usr/bin/tesseract"):
        return "/usr/bin/tesseract"
    # Fallback: system PATH
    found = shutil.which("tesseract")
    if found:
        return found
    # Windows fallback
    return r"C:\Program Files\Tesseract-OCR\tesseract.exe"

TESSERACT_PATH = _find_tesseract()

try:
    import pytesseract as _tess_probe
    _tess_probe.pytesseract.tesseract_cmd = TESSERACT_PATH
except ImportError:
    pass  # ImportError is handled gracefully inside extract_text_from_image()


# ── PDF extraction ─────────────────────────────────────────────────────────────
def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract all text from a PDF file using pdfminer.six."""
    try:
        from pdfminer.high_level import extract_text as _pdfminer_extract
        text = _pdfminer_extract(io.BytesIO(file_bytes))
        return text or ""
    except ImportError:
        raise RuntimeError(
            "pdfminer.six is not installed. Run: pip install pdfminer.six"
        )
    except Exception as e:
        raise RuntimeError(f"PDF extraction failed: {e}")


# ── Image extraction ───────────────────────────────────────────────────────────
def extract_text_from_image(file_bytes: bytes) -> str:
    """Extract text from an image file using pytesseract OCR."""
    try:
        import pytesseract
        from PIL import Image
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH
        img = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(img)
        return text or ""
    except ImportError:
        raise RuntimeError(
            "pytesseract / Pillow not installed. Run: pip install pytesseract pillow"
        )
    except Exception as e:
        raise RuntimeError(f"Image OCR failed: {e}")


# ── Dispatcher ─────────────────────────────────────────────────────────────────
def extract_text(file_bytes: bytes, filename: str) -> str:
    """
    Route to the correct extractor based on file extension.
    Supports: .pdf, .jpg, .jpeg, .png
    """
    name_lower = filename.lower()
    if name_lower.endswith(".pdf"):
        return extract_text_from_pdf(file_bytes)
    elif name_lower.endswith((".jpg", ".jpeg", ".png")):
        return extract_text_from_image(file_bytes)
    else:
        raise ValueError(
            f"Unsupported file type: '{filename}'. Allowed: .pdf, .jpg, .jpeg, .png"
        )


# ── Normalisation ──────────────────────────────────────────────────────────────
def normalize_text(raw: str) -> str:
    """
    Normalise extracted text before hashing:
    - Lowercase
    - Collapse whitespace (tabs, newlines, multi-spaces → single space)
    - Strip leading/trailing whitespace
    """
    text = raw.lower()
    text = re.sub(r"\s+", " ", text)
    text = text.strip()
    return text
