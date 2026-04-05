"""DiE (Detect It Easy) Integration - Packer/compiler/protector detection"""

import json
import os
import subprocess
import shutil
from typing import Annotated, Optional

import ida_nalt

from .rpc import tool
from .tests import test


def _get_input_file_path() -> str:
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"Input file not found: {path}")
    return path


def _find_diec() -> str:
    diec = shutil.which("diec")
    if diec:
        return diec
    candidates = [
        "/opt/die/diec",
        "/usr/local/bin/diec",
        os.path.expanduser("~/die/diec"),
        os.path.expanduser("~/tools/die/diec"),
        "C:\\Tools\\die\\diec.exe",
        "C:\\Program Files\\Detect It Easy\\diec.exe",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        "diec not found. Install Detect It Easy and ensure 'diec' is in PATH. "
        "Download: https://github.com/horsicq/Detect-It-Easy/releases"
    )


def _run_diec(args: list[str], timeout: int = 60) -> str:
    diec = _find_diec()
    try:
        result = subprocess.run(
            [diec] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"diec timed out after {timeout}s")
    except Exception as e:
        raise RuntimeError(f"diec execution failed: {e}")


def _parse_json_output(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw_output": raw}


@tool
def detect_packer() -> dict:
    """Detect packer, protector, compiler, and linker of the current binary using Detect It Easy (DiE).

    Returns a structured result with:
    - detects: list of detected signatures (type, name, version, options)
    - file_type: detected file type (PE, ELF, Mach-O, etc.)
    - is_packed: whether the binary appears to be packed

    Requires 'diec' (Detect It Easy CLI) to be installed.
    """
    filepath = _get_input_file_path()
    raw = _run_diec(["--json", filepath])
    data = _parse_json_output(raw)

    detects = []
    is_packed = False

    if "detects" in data:
        for group in data["detects"]:
            file_type = group.get("filetype", "")
            file_info = group.get("info", "")
            for entry in group.get("values", []):
                item = {
                    "file_type": file_type,
                    "file_info": file_info,
                    "type": entry.get("type", ""),
                    "name": entry.get("name", ""),
                    "version": entry.get("version", ""),
                    "options": entry.get("options", ""),
                    "string": entry.get("string", ""),
                }
                detects.append(item)
                t = item["type"].lower()
                if t in ("packer", "protector", "cryptor", "scrambler"):
                    is_packed = True

    return {
        "file": os.path.basename(filepath),
        "detects": detects,
        "is_packed": is_packed,
        "detect_count": len(detects),
    }


@tool
def detect_packer_detail(
    deep_scan: Annotated[bool, "Enable deep scan mode (slower but more thorough)"] = False,
) -> dict:
    """Detailed packer/protector detection with full DiE output.

    Runs Detect It Easy with verbose output. Optionally enables deep scan
    for more thorough analysis at the cost of speed.

    Returns all matched signatures with confidence levels and metadata.
    """
    filepath = _get_input_file_path()
    args = ["--json"]
    if deep_scan:
        args.append("--deepscan")
    args.append(filepath)

    raw = _run_diec(args, timeout=120 if deep_scan else 60)
    data = _parse_json_output(raw)

    detects = []
    packer_info = []

    if "detects" in data:
        for group in data["detects"]:
            file_type = group.get("filetype", "")
            arch = group.get("arch", "")
            mode = group.get("mode", "")
            endian = group.get("endianess", "")
            group_type = group.get("type", "")

            for entry in group.get("values", []):
                item = {
                    "file_type": file_type,
                    "arch": arch,
                    "mode": mode,
                    "endian": endian,
                    "group_type": group_type,
                    "type": entry.get("type", ""),
                    "name": entry.get("name", ""),
                    "version": entry.get("version", ""),
                    "options": entry.get("options", ""),
                    "string": entry.get("string", ""),
                }
                detects.append(item)
                t = item["type"].lower()
                if t in ("packer", "protector", "cryptor", "scrambler"):
                    packer_info.append(item)

    return {
        "file": os.path.basename(filepath),
        "deep_scan": deep_scan,
        "detects": detects,
        "packer_info": packer_info,
        "is_packed": len(packer_info) > 0,
        "detect_count": len(detects),
    }


@tool
def detect_entropy() -> dict:
    """Analyze binary entropy using DiE to identify packed/encrypted sections.

    High entropy (close to 8.0) in code/data sections strongly suggests
    packing or encryption. Returns per-section entropy values.
    """
    filepath = _get_input_file_path()
    raw = _run_diec(["--json", "--entropy", filepath])
    data = _parse_json_output(raw)

    sections = []
    suspicious = []

    if "records" in data:
        for record in data["records"]:
            section = {
                "name": record.get("name", ""),
                "offset": record.get("offset", ""),
                "size": record.get("size", ""),
                "entropy": record.get("entropy", 0.0),
                "status": record.get("status", ""),
            }
            sections.append(section)
            if section["entropy"] > 6.8:
                suspicious.append(section)

    total_entropy = data.get("total", 0.0)
    overall_status = data.get("status", "")

    return {
        "file": os.path.basename(filepath),
        "total_entropy": total_entropy,
        "status": overall_status,
        "sections": sections,
        "suspicious_sections": suspicious,
        "likely_packed": overall_status == "packed" or total_entropy > 6.8 or len(suspicious) > 0,
    }


@test()
def test_detect_packer():
    result = detect_packer()
    assert isinstance(result, dict)
    assert "file" in result
    assert "detects" in result
    assert "is_packed" in result
    assert isinstance(result["detects"], list)


@test()
def test_detect_packer_detail():
    result = detect_packer_detail(deep_scan=False)
    assert isinstance(result, dict)
    assert "detects" in result
    assert "packer_info" in result


@test()
def test_detect_entropy():
    result = detect_entropy()
    assert isinstance(result, dict)
    assert "total_entropy" in result
    assert "sections" in result
