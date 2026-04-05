#!/usr/bin/env python3
"""Cross-platform launcher for the IDA MCP multi-session server.

- Scans the local analyze/ directory for PE, ELF, or Mach-O binaries.
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
from typing import Any, Dict, List, Tuple


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
    "port": 8745,
    "host": "127.0.0.1",
    "base_session_port": 10000,
    "max_sessions": 10,
    "file_load_timeout": 3600,
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
    return parser


def load_runtime_settings(config_path: Path) -> Tuple[Dict[str, Any], Path]:
    cfg = load_config(config_path)
    base_dir = config_path.parent
    settings: Dict[str, Any] = {
        "mcp_dir": resolve_path(cfg.get("mcp_dir", DEFAULTS["mcp_dir"]), base_dir),
        "uv_value": cfg.get("uv", DEFAULTS["uv"]),
        "analyze_dir": resolve_path(cfg.get("analyze_dir", DEFAULTS["analyze_dir"]), base_dir),
        "host": cfg.get("host", DEFAULTS["host"]),
        "port": int(cfg.get("port", DEFAULTS["port"])),
        "base_session_port": int(cfg.get("base_session_port", DEFAULTS["base_session_port"])),
        "max_sessions": int(cfg.get("max_sessions", DEFAULTS["max_sessions"])),
        "file_load_timeout": int(cfg.get("file_load_timeout", DEFAULTS["file_load_timeout"])),
        "ida_dir": resolve_path(cfg.get("ida_dir", DEFAULTS["ida_dir"]), base_dir),
        "skip_port_check": bool(cfg.get("skip_port_check", False)),
        "no_preload": bool(cfg.get("no_preload", False)),
    }
    return settings, base_dir


def resolve_launcher_dependencies(settings: Dict[str, Any]) -> Tuple[Path, str]:
    mcp_dir = settings["mcp_dir"]
    if mcp_dir is None or not mcp_dir.is_dir():
        raise FileNotFoundError(f"MCP directory not found: {mcp_dir}")

    uv_value = settings["uv_value"]
    uv_path = shutil.which(str(uv_value))
    if not uv_path:
        raise FileNotFoundError(f"uv not found (looked for '{uv_value}')")

    return mcp_dir, uv_path


def discover_preload_files(analyze_dir: Path | None, no_preload: bool) -> List[str]:
    if no_preload:
        return []
    if analyze_dir is None or not analyze_dir.is_dir():
        raise FileNotFoundError(f"analyze directory not found: {analyze_dir}")

    files = collect_binaries(analyze_dir)
    if not files:
        raise FileNotFoundError(
            f"No PE/ELF/Mach-O binaries found in {analyze_dir}. "
            f"Set no_preload = true in config.toml to start empty."
        )
    return files


def cleanup_ports(port: int, base_session_port: int, max_sessions: int) -> None:
    kill_port_process(port)
    for session_port in range(base_session_port, base_session_port + (max_sessions * 2)):
        kill_port_process(session_port)


def validate_main_port(host: str, port: int, skip_port_check: bool) -> None:
    if not skip_port_check and not port_available(host, port):
        raise OSError(f"{host}:{port} looks busy. Free it or set skip_port_check = true if intentional.")


def build_launch_command(settings: Dict[str, Any], uv_path: str, files: List[str]) -> List[str]:
    return [
        uv_path,
        "run",
        "idalib-mcp-multisession",
        "--host",
        settings["host"],
        "--port",
        str(settings["port"]),
        "--base-session-port",
        str(settings["base_session_port"]),
        "--max-sessions",
        str(settings["max_sessions"]),
        "--file-load-timeout",
        str(settings["file_load_timeout"]),
        "--verbose",
        *files,
    ]


def print_launch_summary(settings: Dict[str, Any], uv_path: str, mcp_dir: Path, files: List[str]) -> None:
    print("=== IDA MCP Multi-Session Server ===")
    print(f"uv: {uv_path}")
    print(f"MCP dir: {mcp_dir}")
    print(f"Host: {settings['host']}")
    print(f"Port: {settings['port']}")
    print(f"Base session port: {settings['base_session_port']}")
    print(f"Max sessions: {settings['max_sessions']}")
    print(f"File load timeout: {settings['file_load_timeout']}s")
    if settings["ida_dir"]:
        print(f"IDADIR: {settings['ida_dir']}")
    if settings["no_preload"]:
        print("Analyze dir: (skipped, no_preload = true)")
        print("Files: none (empty start)")
    else:
        print(f"Analyze dir: {settings['analyze_dir']}")
        print("Files:")
        for file_path in files:
            print(f"  - {file_path}")
    print("====================================")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config_path = args.config.resolve()

    try:
        settings, _ = load_runtime_settings(config_path)
        mcp_dir, uv_path = resolve_launcher_dependencies(settings)
        files = discover_preload_files(settings["analyze_dir"], settings["no_preload"])
        cleanup_ports(settings["port"], settings["base_session_port"], settings["max_sessions"])
        validate_main_port(settings["host"], settings["port"], settings["skip_port_check"])
    except (FileNotFoundError, OSError, ValueError) as e:
        print(f"[ERROR] {e}")
        return 1

    env = os.environ.copy()
    if settings["ida_dir"]:
        env["IDADIR"] = str(settings["ida_dir"])

    cmd = build_launch_command(settings, uv_path, files)
    print_launch_summary(settings, uv_path, mcp_dir, files)

    try:
        return subprocess.call(cmd, env=env, cwd=mcp_dir)
    except FileNotFoundError:
        print("[ERROR] Failed to start server (check uv installation and PATH)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
