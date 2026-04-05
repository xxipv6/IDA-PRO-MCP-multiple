"""Automated unpacking - UPX + unipacker generic unpacking"""

import json
import os
import shutil
import subprocess
import threading
from typing import Annotated

import ida_nalt

from .rpc import tool
from .tests import test


def _get_input_file_path() -> str:
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"Input file not found: {path}")
    return path


def _get_unpack_dir(filepath: str) -> str:
    d = os.path.join(os.path.dirname(filepath), "unpacked")
    os.makedirs(d, exist_ok=True)
    return d


def _detect_packer_type(filepath: str) -> dict:
    """Run diec to identify packer type."""
    diec = shutil.which("diec")
    if not diec:
        return {"packer": "unknown", "is_packed": False}
    try:
        result = subprocess.run(
            [diec, "--json", filepath],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(result.stdout)
    except Exception:
        return {"packer": "unknown", "is_packed": False}

    packer_name = ""
    packer_type = ""
    is_packed = False

    for group in data.get("detects", []):
        for entry in group.get("values", []):
            t = entry.get("type", "").lower()
            if t in ("packer", "protector", "cryptor", "scrambler"):
                is_packed = True
                packer_name = entry.get("name", "").lower()
                packer_type = t

    return {
        "packer": packer_name,
        "packer_type": packer_type,
        "is_packed": is_packed,
    }


def _unpack_upx(filepath: str, output: str) -> dict:
    """Unpack UPX packed binary."""
    upx = shutil.which("upx")
    if not upx:
        raise FileNotFoundError("upx not found in PATH")

    shutil.copy2(filepath, output)
    result = subprocess.run(
        [upx, "-d", output],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        os.remove(output)
        raise RuntimeError(f"UPX unpack failed: {result.stderr.strip()}")

    return {
        "method": "upx",
        "output": output,
        "size_before": os.path.getsize(filepath),
        "size_after": os.path.getsize(output),
        "stdout": result.stdout.strip(),
    }


def _unpack_generic(filepath: str, output: str) -> dict:
    """Unpack using unipacker (emulation-based, PE32 only)."""
    try:
        from unipacker.core import UnpackerEngine, Sample
    except ImportError:
        raise RuntimeError("unipacker not installed. Run: pip install unipacker")

    try:
        sample = Sample(filepath)
    except Exception as e:
        raise RuntimeError(f"unipacker cannot parse file: {e}")

    engine = UnpackerEngine(sample, output)

    done_event = threading.Event()

    class AutoClient:
        def emu_started(self): pass
        def emu_paused(self): done_event.set()
        def emu_resumed(self): pass
        def emu_done(self): done_event.set()
        def address_updated(self, addr): pass

    client = AutoClient()
    engine.register_client(client)

    emu_thread = threading.Thread(target=engine.emu, daemon=True)
    emu_thread.start()
    done_event.wait(timeout=300)

    if emu_thread.is_alive():
        engine.stop()
        emu_thread.join(timeout=10)

    # Dump the unpacked result
    try:
        sample.unpacker.dump(engine.uc, engine.apicall_handler, sample, path=output)
    except Exception as e:
        raise RuntimeError(f"Dump failed: {e}")

    if not os.path.isfile(output):
        raise RuntimeError("Unpack produced no output file")

    return {
        "method": "unipacker",
        "unpacker_used": sample.unpacker.__class__.__name__,
        "output": output,
        "size_before": os.path.getsize(filepath),
        "size_after": os.path.getsize(output),
    }


@tool
def auto_unpack(
    output_name: Annotated[str, "Output filename for unpacked binary (optional)"] = "",
) -> dict:
    """Automatically unpack the current binary.

    Detection flow:
    1. Identify packer using DiE (diec)
    2. UPX → use native 'upx -d' (fast, reliable)
    3. Other PE32 packers → use unipacker (emulation-based)
    4. Unknown/unsupported → report what was detected

    Returns the unpacked file path, method used, and size comparison.
    The unpacked file is saved in an 'unpacked/' subdirectory next to the original.
    """
    filepath = _get_input_file_path()
    basename = os.path.basename(filepath)
    unpack_dir = _get_unpack_dir(filepath)

    if not output_name:
        output_name = f"{os.path.splitext(basename)[0]}_unpacked{os.path.splitext(basename)[1]}"
    output = os.path.join(unpack_dir, output_name)

    # Step 1: Identify packer
    info = _detect_packer_type(filepath)

    if not info["is_packed"]:
        return {
            "file": basename,
            "status": "not_packed",
            "message": "DiE did not detect any packer. Binary may not be packed.",
            "detection": info,
        }

    # Step 2: Route to appropriate unpacker
    packer = info["packer"]

    if packer == "upx":
        result = _unpack_upx(filepath, output)
        return {
            "file": basename,
            "status": "success",
            "detection": info,
            **result,
        }

    # Step 3: Try unipacker for PE32
    try:
        result = _unpack_generic(filepath, output)
        return {
            "file": basename,
            "status": "success",
            "detection": info,
            **result,
        }
    except Exception as e:
        return {
            "file": basename,
            "status": "failed",
            "detection": info,
            "error": str(e),
            "message": f"Detected {info['packer']} ({info['packer_type']}) but automated unpacking failed. "
                       "Manual unpacking may be required.",
        }


@tool
def unpack_upx(
    output_name: Annotated[str, "Output filename for unpacked binary (optional)"] = "",
) -> dict:
    """Unpack a UPX-packed binary using native 'upx -d'.

    Fast and reliable for UPX-packed binaries. Preserves the original file
    and saves the unpacked version in an 'unpacked/' subdirectory.
    """
    filepath = _get_input_file_path()
    basename = os.path.basename(filepath)
    unpack_dir = _get_unpack_dir(filepath)

    if not output_name:
        output_name = f"{os.path.splitext(basename)[0]}_unpacked{os.path.splitext(basename)[1]}"
    output = os.path.join(unpack_dir, output_name)

    result = _unpack_upx(filepath, output)
    return {"file": basename, "status": "success", **result}


@tool
def unpack_generic(
    output_name: Annotated[str, "Output filename for unpacked binary (optional)"] = "",
) -> dict:
    """Unpack a packed PE32 binary using emulation-based generic unpacking (unipacker).

    Supports: UPX, ASPack, FSG, PEtite, YZPack, MEW, MPRESS, PECompact,
    and unknown packers via automatic OEP detection.

    Note: Only supports PE32 (32-bit Windows executables).
    The unpacked file is saved in an 'unpacked/' subdirectory.
    """
    filepath = _get_input_file_path()
    basename = os.path.basename(filepath)
    unpack_dir = _get_unpack_dir(filepath)

    if not output_name:
        output_name = f"{os.path.splitext(basename)[0]}_unpacked{os.path.splitext(basename)[1]}"
    output = os.path.join(unpack_dir, output_name)

    result = _unpack_generic(filepath, output)
    return {"file": basename, "status": "success", **result}


@test()
def test_auto_unpack():
    result = auto_unpack()
    assert isinstance(result, dict)
    assert "file" in result
    assert "status" in result
