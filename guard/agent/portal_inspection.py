"""Inspect portal content on this PC; only counts leave the local process."""
import base64
import os
import tempfile
from pathlib import Path
from rules import scan_text
from files import inspect_file

KEYS = ("phone", "email", "account", "card", "rrn", "rrn_high", "rrn_mid", "rrn_low")

def metadata(data):
    out = {}
    if type(data.get("inspectable")) is bool:
        out["inspectable"] = data["inspectable"]
    if "pattern_hits" in data:
        hits = data["pattern_hits"]
        if not isinstance(hits, dict): raise ValueError("Invalid counts")
        out["pattern_hits"] = {}
        for key in KEYS:
            value = hits.get(key, 0)
            if type(value) is not int or not 0 <= value <= 100000000: raise ValueError("Invalid count")
            out["pattern_hits"][key] = value
    if "text_length" in data:
        value = data["text_length"]
        if type(value) is not int or not 0 <= value <= 100000000: raise ValueError("Invalid length")
        out["text_length"] = value
    for key in ("reason", "file_kind"):
        if key in data:
            if not isinstance(data[key], str) or len(data[key]) > 256: raise ValueError("Invalid inspection metadata")
            out[key] = data[key]
    return out

def inspect_content(data):
    if not isinstance(data, dict): raise ValueError("Object required")
    if "text" in data:
        text = data["text"]
        if not isinstance(text, str) or len(text) > 1000000: raise ValueError("Text too large")
        return {"inspectable": True, "text_length": len(text), "pattern_hits": scan_text(text)}
    raw = data.get("file_base64")
    name = data.get("file_name")
    if not isinstance(raw, str) or len(raw) > 28000000 or not isinstance(name, str): raise ValueError("Invalid file")
    content = base64.b64decode(raw, validate=True)
    if len(content) > 20*1024*1024: raise ValueError("File too large")
    suffix = Path(name).suffix.lower()
    if suffix not in (".csv", ".tsv", ".txt", ".xlsx"):
        return {"inspectable": False, "reason": "UNSUPPORTED_FORMAT"}
    path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            path = f.name
            f.write(content)
        return inspect_file(path)
    finally:
        if path: os.unlink(path)
