#!/usr/bin/env python3
"""Cross-platform launcher for the IDA MCP multi-session server.

- Scans the local analyze/ directory for PE or ELF binaries.
- Starts idalib-mcp-multisession via uv with the detected files preloaded.
- Works on Windows, macOS, and Linux.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List


def is_supported_binary(path: Path) -> bool:
    """Return True if file looks like PE, ELF, or Mach-O based on magic bytes."""
    try:
        with path.open("rb") as f:
            signature = f.read(4)
    except OSError:
        return False

    # PE: MZ
    if signature.startswith(b"MZ"):
        return True
    # ELF: \x7fELF
    if signature.startswith(b"\x7fELF"):
        return True
    # Mach-O magic numbers (big and little endian for 32/64-bit and universal)
    mach_o_magics = {
        b"\xFE\xED\xFA\xCE",  # MH_MAGIC (32-bit, big endian)
        b"\xCE\xFA\xED\xFE",  # MH_MAGIC (32-bit, little endian)
        b"\xFE\xED\xFA\xCF",  # MH_MAGIC_64 (64-bit, big endian)
        b"\xCF\xFA\xED\xFE",  # MH_MAGIC_64 (64-bit, little endian)
        b"\xCA\xFE\xBA\xBE",  # FAT_MAGIC (universal binary, big endian)
        b"\xBE\xBA\xFE\xCA",  # FAT_MAGIC (universal binary, little endian)
        b"\xCA\xFE\xBA\xBF",  # FAT_MAGIC_64 (universal binary 64-bit, big endian)
        b"\xBF\xBA\xFE\xCA",  # FAT_MAGIC_64 (universal binary 64-bit, little endian)
    }
    return signature in mach_o_magics


def collect_binaries(analyze_dir: Path) -> List[str]:
    files: List[str] = []
    for entry in sorted(analyze_dir.iterdir()):
        if entry.is_file() and is_supported_binary(entry):
            files.append(str(entry.resolve()))
    return files


def kill_port_process(port: int) -> bool:
    """Kill processes listening on the specified port. Returns True if any process was killed."""
    if sys.platform == "win32":
        # Windows: use netstat and taskkill
        try:
            result = subprocess.run(
                f'netstat -ano | findstr ":{port}"',
                shell=True,
                capture_output=True,
                text=True,
            )
            pids = set()
            for line in result.stdout.strip().split("\n"):
                if line and "LISTENING" in line:
                    parts = line.split()
                    if parts:
                        pids.add(parts[-1])
            for pid in pids:
                if pid.isdigit():
                    subprocess.run(f'taskkill /F /PID {pid}', shell=True, capture_output=True)
                    print(f"[INFO] Killed process {pid} on port {port}")
            return len(pids) > 0
        except Exception:
            return False
    else:
        # macOS/Linux: use lsof
        try:
            result = subprocess.run(
                f"lsof -i :{port} -t",
                shell=True,
                capture_output=True,
                text=True,
            )
            pids = result.stdout.strip().split("\n")
            pids = [p for p in pids if p.isdigit()]
            for pid in pids:
                subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True)
                print(f"[INFO] Killed process {pid} on port {port}")
            return len(pids) > 0
        except Exception:
            return False


def port_available(host: str, port: int) -> bool:
    """Check if a TCP port is free on the specified host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


DEFAULTS: Dict[str, Any] = {
    "port": 8746,
    "host": "127.0.0.1",
    "base_session_port": 10000,
    "analyze_dir": str(Path(__file__).parent / "analyze"),
    "ida_dir": None,
    "uv": "uv",
    "skip_port_check": False,
    "no_preload": False,
    "mcp_dir": str(Path(__file__).parent / "ida-pro-mcp"),
}


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from TOML; fall back to defaults when absent."""
    config: Dict[str, Any] = DEFAULTS.copy()
    if config_path.is_file():
        with config_path.open("rb") as f:
            raw = tomllib.load(f)
        config.update({k: raw.get(k, v) for k, v in DEFAULTS.items()})
    return config


def pick(value_cli: Any, value_cfg: Any, default: Any) -> Any:
    return value_cli if value_cli is not None else (value_cfg if value_cfg is not None else default)


def resolve_path(value: str | Path | None, base: Path) -> Path | None:
    if value is None:
        return None
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = (base / p).resolve()
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start IDA MCP multi-session server (cross-platform)")
    parser.add_argument("--config", type=Path, default=Path(__file__).parent / "config.toml", help="Path to config.toml")
    parser.add_argument("--port", type=int, default=None, help="Main MCP HTTP port")
    parser.add_argument("--host", default=None, help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--base-session-port", type=int, default=None, help="Base port for session workers")
    parser.add_argument("--analyze-dir", type=Path, default=None, help="Directory containing binaries to preload")
    parser.add_argument("--ida-dir", type=Path, default=None, help="Optional IDA installation path (sets IDADIR env)")
    parser.add_argument("--uv", default=None, help="uv executable to use")
    parser.add_argument("--skip-port-check", action="store_true", help="Start even if the port appears busy")
    parser.add_argument("--no-preload", action="store_true", help="Do not preload binaries; start empty for manual session creation")
    parser.add_argument("--mcp-dir", type=Path, default=None, help="Directory containing ida-pro-mcp project (pyproject/uv.lock)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config_path = args.config.resolve()
    cfg = load_config(config_path)
    base_dir = config_path.parent

    mcp_dir = resolve_path(pick(args.mcp_dir, cfg.get("mcp_dir"), DEFAULTS["mcp_dir"]), base_dir)
    if mcp_dir is None or not mcp_dir.is_dir():
        print(f"[ERROR] MCP directory not found: {mcp_dir}")
        return 1

    uv_value = pick(args.uv, cfg.get("uv"), DEFAULTS["uv"])
    uv_path = shutil.which(str(uv_value))
    if not uv_path:
        print(f"[ERROR] uv not found (looked for '{uv_value}')")
        return 1

    analyze_dir = resolve_path(pick(args.analyze_dir, cfg.get("analyze_dir"), DEFAULTS["analyze_dir"]), base_dir)
    host = pick(args.host, cfg.get("host"), DEFAULTS["host"])
    port = int(pick(args.port, cfg.get("port"), DEFAULTS["port"]))
    base_session_port = int(pick(args.base_session_port, cfg.get("base_session_port"), DEFAULTS["base_session_port"]))
    ida_dir = resolve_path(pick(args.ida_dir, cfg.get("ida_dir"), DEFAULTS["ida_dir"]), base_dir)
    skip_port_check = args.skip_port_check or bool(cfg.get("skip_port_check", False))
    no_preload = args.no_preload or bool(cfg.get("no_preload", False))

    files: List[str] = []
    if not no_preload:
        if analyze_dir is None or not analyze_dir.is_dir():
            print(f"[ERROR] analyze directory not found: {analyze_dir}")
            return 1
        files = collect_binaries(analyze_dir)
        if not files:
            print(f"[ERROR] No PE/ELF binaries found in {analyze_dir}. Use --no-preload to start empty.")
            return 1

    # Kill any existing processes on the main port and session ports
    kill_port_process(port)
    # Also kill processes on session ports (base_session_port to base_session_port + 10)
    for session_port in range(base_session_port, base_session_port + 10):
        kill_port_process(session_port)

    if not skip_port_check and not port_available(host, port):
        print(f"[ERROR] {host}:{port} looks busy. Free it or rerun with --skip-port-check if intentional.")
        return 1

    env = os.environ.copy()
    if ida_dir:
        env["IDADIR"] = str(ida_dir)

    cmd = [
        uv_path,
        "run",
        "idalib-mcp-multisession",
        "--host",
        host,
        "--port",
        str(port),
        "--base-session-port",
        str(base_session_port),
        "--verbose",  # Enable debug logging
        *files,
    ]

    print("=== IDA MCP Multi-Session Server ===")
    print(f"uv: {uv_path}")
    print(f"MCP dir: {mcp_dir}")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Base session port: {base_session_port}")
    if ida_dir:
        print(f"IDADIR: {ida_dir}")
    if no_preload:
        print("Analyze dir: (skipped, --no-preload)")
        print("Files: none (empty start)")
    else:
        print(f"Analyze dir: {analyze_dir}")
        print("Files:")
        for f in files:
            print(f"  - {f}")
    print("====================================")

    try:
        return subprocess.call(cmd, env=env, cwd=mcp_dir)
    except FileNotFoundError:
        print("[ERROR] Failed to start server (check uv installation and PATH)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
