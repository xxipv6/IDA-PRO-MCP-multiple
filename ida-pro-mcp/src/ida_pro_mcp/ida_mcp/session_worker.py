"""Session Worker - Runs IDALib in a separate process

This module is imported and executed in a separate process for each session
to provide isolation between different IDA Pro instances.
"""

import logging
import os
import signal
import sys
from pathlib import Path

# Must be imported before any ida* imports when using idalib
import idapro
import ida_auto

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False) -> None:
    """Setup logging for the worker process"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(name)s: %(message)s",
        force=True,  # Override any existing config
    )

    # Set idapro logging
    idapro.enable_console_messages(verbose)


def _signal_handler(signum, frame):
    """Handle signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down...")
    idapro.close_database()
    sys.exit(0)


def run_idalib_session(
    file_path: str,
    port: int,
    idb_path: str | None,
    auto_analysis: bool,
    ready_file: Path | None = None,
) -> None:
    """Run an IDALib session in a separate process

    This function is designed to run as a standalone script.
    It opens the IDA database, runs auto-analysis, and starts the MCP server.

    Args:
        file_path: Path to the binary file to analyze
        port: Port number for the MCP server
        idb_path: Optional path for the IDB file
        auto_analysis: Whether to run auto analysis
        ready_file: Optional path to a file to create when ready
    """

    def signal_ready() -> None:
        """Signal that the session is ready"""
        if ready_file:
            ready_file.touch()
            logger.debug(f"Created ready file: {ready_file}")

    try:
        # Setup logging
        _setup_logging(verbose=False)

        logger.info(f"Starting IDALib session for {file_path} on port {port}")

        # Verify file exists
        if not Path(file_path).exists():
            logger.error(f"File not found: {file_path}")
            signal_ready()
            return

        # Open database
        logger.info(f"Opening database: {file_path}")
        if idb_path:
            logger.info(f"  IDB will be cached at: {idb_path}")

        result = idapro.open_database(
            file_path,
            run_auto_analysis=auto_analysis,
        )

        if result:
            logger.error(f"Failed to open database: {file_path} (error code: {result})")
            signal_ready()  # Signal even on failure so parent doesn't hang
            return

        # Wait for auto analysis to complete
        logger.debug("Waiting for auto analysis...")
        ida_auto.auto_wait()

        logger.info("Database loaded successfully")

        # Setup signal handlers for clean shutdown
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        # Import and setup MCP server
        # Inside IDALib, idaapi is available, so we can import normally
        # We just need to ensure the package structure is correct

        # IMPORTANT: Both IDA and our project have http.py that shadows stdlib http module
        # We need to manually load http from the standard library
        # Note: sys is already imported at module level, don't re-import to avoid UnboundLocalError
        import importlib.util
        import os

        # Find the standard library http module
        stdlib_paths = [p for p in sys.path if p and ('lib' in p or 'site-packages' in p) and 'IDA' not in p and 'ida_pro_mcp' not in p]
        stdlib_paths.insert(0, os.path.dirname(sys.executable) + '/Lib')

        # Temporarily modify sys.path to prioritize stdlib
        original_sys_path = sys.path.copy()
        sys.path = [p for p in sys.path if 'IDA' not in p and 'ida_pro_mcp' not in p]

        # Import http modules from stdlib
        import http
        import http.server
        import http.client

        # Restore original sys.path
        sys.path = original_sys_path

        # Find the package root (ida-pro-mcp/src/ida_pro_mcp)
        # We're at: ida-pro-mcp/src/ida_pro_mcp/ida_mcp/session_worker.py
        # Package root is: ida-pro-mcp/src
        pkg_root = Path(__file__).parent.parent.parent
        if str(pkg_root) not in sys.path:
            sys.path.insert(0, str(pkg_root))

        logger.info(f"Package root: {pkg_root}")
        logger.info(f"Importing ida_pro_mcp.ida_mcp package (registers all tools)")

        # IMPORTANT: Import the package first to trigger __init__.py which imports
        # all api_* modules and registers their @tool decorators
        try:
            import ida_pro_mcp.ida_mcp
            logger.info(f"Successfully imported ida_pro_mcp.ida_mcp package")
        except Exception as e:
            logger.error(f"Failed to import ida_pro_mcp.ida_mcp: {e}")
            import traceback
            traceback.print_exc()
            raise

        logger.info(f"Importing MCP server from ida_pro_mcp.ida_mcp.rpc")

        # Now we can import normally - inside IDALib, idaapi is available
        # so the ida_mcp package imports will work
        from ida_pro_mcp.ida_mcp.rpc import set_download_base_url, MCP_SERVER

        set_download_base_url(f"http://127.0.0.1:{port}")

        # Log how many tools are registered
        num_tools = len(MCP_SERVER.tools.methods)
        logger.info(f"Registered {num_tools} MCP tools")
        for tool_name in sorted(MCP_SERVER.tools.methods.keys()):
            logger.debug(f"  - {tool_name}")

        logger.info(f"MCP server starting on port {port}")

        # Signal ready before starting the blocking serve call
        signal_ready()
        logger.info(f"Session ready signal sent, starting MCP server")

        # Start the MCP server in blocking mode (runs on main thread)
        # This ensures IDA API calls work correctly without threading issues
        try:
            MCP_SERVER.serve(host="127.0.0.1", port=port, background=False)
        finally:
            # Clean shutdown when serve() returns
            logger.info("MCP server stopped, closing IDA database...")
            idapro.close_database()
            logger.info("Session closed")

    except Exception as e:
        logger.exception(f"Error in IDALib session: {e}")
        signal_ready()  # Signal even on error
        sys.exit(1)


def run_idalib_session_main() -> None:
    """Entry point for running as a standalone process (for testing)"""
    import argparse

    parser = argparse.ArgumentParser(description="IDA Pro MCP Session Worker")
    parser.add_argument("file_path", type=str, help="Path to binary file")
    parser.add_argument("--port", type=int, required=True, help="Port for MCP server")
    parser.add_argument("--idb-path", type=str, default=None, help="Path for IDB file")
    parser.add_argument(
        "--no-auto-analysis",
        action="store_true",
        help="Disable auto analysis",
    )
    parser.add_argument("--ready-file", type=str, default=None, help="Path to ready signal file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    # Run with file-based signaling
    ready_file = Path(args.ready_file) if args.ready_file else None
    run_idalib_session(
        file_path=args.file_path,
        port=args.port,
        idb_path=args.idb_path,
        auto_analysis=not args.no_auto_analysis,
        ready_file=ready_file,
    )


if __name__ == "__main__":
    run_idalib_session_main()
