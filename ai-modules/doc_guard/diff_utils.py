"""
diff_utils.py
Human-readable text comparison using difflib.

Compares two normalised text strings and returns a list of readable
change descriptions (added / removed word-level chunks).
"""

import difflib
from typing import List, Dict


def compute_diff(original: str, modified: str) -> List[Dict]:
    """
    Word-level diff between two normalised text strings.

    Returns a list of change dicts:
      { "type": "removed" | "added" | "changed",
        "original": str,
        "modified": str }
    """
    orig_words = original.split()
    mod_words  = modified.split()

    matcher = difflib.SequenceMatcher(None, orig_words, mod_words, autojunk=False)
    changes: List[Dict] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        orig_chunk = " ".join(orig_words[i1:i2])
        mod_chunk  = " ".join(mod_words[j1:j2])

        if tag == "replace":
            changes.append({
                "type":     "changed",
                "original": orig_chunk,
                "modified": mod_chunk,
            })
        elif tag == "delete":
            changes.append({
                "type":     "removed",
                "original": orig_chunk,
                "modified": "",
            })
        elif tag == "insert":
            changes.append({
                "type":     "added",
                "original": "",
                "modified": mod_chunk,
            })

    return changes


def similarity_ratio(original: str, modified: str) -> float:
    """Return a 0-1 similarity score between the two texts."""
    return difflib.SequenceMatcher(None, original, modified).ratio()
