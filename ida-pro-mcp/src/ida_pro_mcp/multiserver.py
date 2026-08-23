"""Multi-Session MCP Server for IDA Pro

This module provides the main entry point for running a multi-session IDA Pro MCP server.
It manages multiple IDALib instances, each analyzing a different binary file.

Usage:
    python -m ida_pro_mcp.multiserver /path/to/binary1 /path/to/binary2
    uv run idalib-multiserver --port 8745 /path/to/binary
"""

import argparse
import asyncio
import logging
import signal
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from . import api_session
from ._session_loader import load_session_module
from .tool_manifest import load_analysis_tools


_session_module = load_session_module()
init_session_manager = _session_module.init_session_manager
get_session_manager = _session_module.get_session_manager

_zeromcp_dir = str(Path(__file__).parent / "ida_mcp")
if _zeromcp_dir not in sys.path:
    sys.path.insert(0, _zeromcp_dir)
from zeromcp import McpServer, McpRpcRegistry, McpHttpRequestHandler, McpToolError
if _zeromcp_dir in sys.path:
    sys.path.remove(_zeromcp_dir)

logger = logging.getLogger(__name__)


def _build_session_tools() -> list[dict]:
    """Session management tool definitions (always served locally)"""
    return [
        {
            "name": "session_create",
            "description": "Create a new analysis session",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "auto_analysis": {"type": "boolean"},
                },
                "required": ["file_path"],
            },
        },
        {
            "name": "session_list",
            "description": "List all analysis sessions",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "session_get",
            "description": "Get detailed information about a specific session",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "session_switch",
            "description": "Switch the active session",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "session_close",
            "description": "Close an analysis session",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "session_active",
            "description": "Get the active session",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "session_status",
            "description": "Get session manager status",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


class MultiSessionMCPServer:
    """MCP Server that supports multiple IDA Pro analysis sessions"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8745,
        base_session_port: int = 10000,
        max_sessions: int = 10,
        file_load_timeout: float = 3600,
        idb_cache_dir: Optional[str] = None,
        unsafe: bool = False,
    ):
        self.host = host
        self.port = port
        self.base_session_port = base_session_port
        self.max_sessions = max_sessions
        self.file_load_timeout = file_load_timeout
        self.unsafe = unsafe

        # Per-session queue locks: requests to the same session are serialized
        # (single-threaded worker), Multiple agents can queue up and
        # each gets the full timeout window.
        # These are asyncio locks because all proxy work runs on a single
        # dedicated event loop (see serve()) — a threading.Lock held across
        # an await would freeze that loop.
        self._session_locks: dict[str, asyncio.Lock] = {}
        self._session_locks_lock = threading.Lock()

        # Dedicated event loop in its own thread. Request threads submit
        # coroutines to it instead of building a throwaway loop per request.
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None

        # Initialize session manager
        self.session_manager = init_session_manager(
            base_port=base_session_port,
            max_sessions=max_sessions,
            file_load_timeout=file_load_timeout,
            idb_cache_dir=idb_cache_dir,
            host=host,
        )

        # Create MCP server
        self.mcp_server = McpServer("ida-pro-mcp-multisession", version="2.0.0")

        # Load analysis tool schemas locally (no IDA needed) so tools/list
        # always exposes the full tool set, even with no active session.
        # Falls back to proxying tools/list to the active session on failure.
        try:
            self._analysis_tools: Optional[list] = load_analysis_tools()
            logger.info(f"Loaded {len(self._analysis_tools)} analysis tool schemas")
        except Exception:
            logger.exception(
                "Failed to load analysis tool schemas locally; "
                "tools/list will fall back to proxying the active session"
            )
            self._analysis_tools = None

        logger.info(f"Multi-session MCP server initialized on {host}:{port}")
        logger.info(f"  Base session port: {base_session_port}")
        logger.info(f"  Max sessions: {max_sessions}")

    async def proxy_tools_list(self) -> dict:
        """Return the full tool list: session management tools + analysis tools.

        Analysis tool schemas are loaded locally at startup (see
        tool_manifest), so the complete list is served even with no
        active session — e.g. an empty no_preload start, where the client
        still needs the analysis tools visible to work with sessions it
        creates later.
        """
        session_tools = _build_session_tools()

        if self._analysis_tools is not None:
            return {"tools": session_tools + self._analysis_tools}

        # Fallback (local schema load failed): proxy to the active session
        manager = get_session_manager()
        session = await manager.get_active_session()

        if not session:
            # Return only session management tools when no session is active
            logger.debug("No active session, returning only session management tools")
            return {"tools": session_tools}

        # Forward to active session
        session_url = f"http://127.0.0.1:{session.port}/mcp"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10, read=50, write=10, pool=10)) as http_client:
                response = await http_client.post(
                    session_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "tools/list",
                        "id": 1,
                    },
                )
            response.raise_for_status()
            result = response.json()

            # Add session management tools to the result
            if "result" in result and "tools" in result["result"]:
                result["result"]["tools"] = session_tools + result["result"]["tools"]
                logger.debug(f"Retrieved {len(result['result']['tools'])} tools from session {session.id}")
                return result["result"]
            else:
                logger.warning(f"Invalid response from session {session.id}: {result}")
                # Return session tools only when response is invalid
                return {"tools": session_tools}

        except httpx.HTTPError as e:
            logger.error(f"Failed to get tools list from session {session.id}: {e}")
            logger.error(f"Session URL: {session_url}, Session status: {session.status}")
            # Return only session management tools when session is unavailable
            return {"tools": session_tools}

    async def proxy_tools_call(
        self,
        name: str,
        arguments: Optional[dict] = None,
        _meta: Optional[dict] = None,
    ) -> dict:
        """Proxy a tool call to the appropriate session"""
        # Extract session_id from arguments if present
        session_id = None
        if arguments:
            session_id = arguments.pop("_session_id", None)

        # Handle session management tools locally
        if name.startswith("session_"):
            return await self._handle_session_tool(name, arguments)

        # Proxy to active/target session
        manager = get_session_manager()
        try:
            session = await manager.get_session_for_call(session_id)
        except RuntimeError as e:
            return {
                "content": [{"type": "text", "text": str(e)}],
                "isError": True,
            }

        session_url = f"http://127.0.0.1:{session.port}/mcp"

        # Acquire per-session lock — requests queue here instead of being rejected.
        # Each request gets the full timeout once it reaches the front of the queue.
        with self._session_locks_lock:
            lock = self._session_locks.get(session.id)
            if lock is None:
                lock = asyncio.Lock()
                self._session_locks[session.id] = lock

        async with lock:
            try:
                logger.debug(f"Sending request to {session_url} for tool {name} with args: {arguments}")
                async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10, read=120, write=10, pool=10)) as http_client:
                    response = await http_client.post(
                        session_url,
                        json={
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": name,
                                "arguments": arguments,
                            },
                            "id": 1,
                        },
                    )
                logger.debug(f"Response status: {response.status_code}, body: {response.text[:500]}")
                response.raise_for_status()
                json_response = response.json()
                if "result" in json_response:
                    return json_response["result"]
                if "error" in json_response:
                    error = json_response["error"]
                    error_msg = error.get("message", "Unknown session error")
                    logger.error(f"Session {session.id} returned error: {error_msg}")
                    return {
                        "content": [{"type": "text", "text": f"Session error: {error_msg}"}],
                        "isError": True,
                    }
                return json_response
            except httpx.HTTPError as e:
                logger.error(f"Failed to call tool {name} on session {session.id}: {e}")
                logger.error(f"Session URL: {session_url}, Session status: {session.status.value}")
                return {
                    "content": [{"type": "text", "text": f"Failed to reach session {session.id}: {e}"}],
                    "isError": True,
                }
            except Exception as e:
                logger.exception(f"Unexpected error calling tool {name} on session {session.id}: {e}")
                return {
                    "content": [{"type": "text", "text": f"Unexpected error: {e}"}],
                    "isError": True,
                }

    async def _handle_session_tool(self, name: str, arguments: Optional[dict]) -> dict:
        """Handle session management tool calls"""

        func_map = {
            "session_create": api_session.session_create,
            "session_list": api_session.session_list,
            "session_get": api_session.session_get,
            "session_switch": api_session.session_switch,
            "session_close": api_session.session_close,
            "session_active": api_session.session_active,
            "session_status": api_session.session_status,
        }

        func = func_map.get(name)
        if not func:
            return {
                "content": [{"type": "text", "text": f"Unknown session tool: {name}"}],
                "isError": True,
            }

        try:
            result = await func(**(arguments or {}))

            # Drop the per-session queue lock when a session is closed so the
            # lock dict doesn't grow unbounded over the server's lifetime.
            if name == "session_close" and arguments:
                closed_id = arguments.get("session_id")
                if closed_id:
                    with self._session_locks_lock:
                        self._session_locks.pop(closed_id, None)

            # Convert result to string for content
            result_str = str(result)

            # Only include structuredContent if it's a dict (record), not a list
            if isinstance(result, dict):
                return {
                    "content": [{"type": "text", "text": result_str}],
                    "structuredContent": result,
                    "isError": False,
                }
            else:
                # For lists and other types, don't include structuredContent
                return {
                    "content": [{"type": "text", "text": result_str}],
                    "isError": False,
                }
        except Exception as e:
            logger.exception(f"Error in session tool {name}: {e}")
            return {
                "content": [{"type": "text", "text": f"Error: {e}"}],
                "isError": True,
            }

    def _start_event_loop(self) -> None:
        """Start the dedicated event loop thread (idempotent)"""
        if self._loop is not None:
            return
        loop = asyncio.new_event_loop()
        self._loop = loop
        self._loop_thread = threading.Thread(
            target=loop.run_forever, name="mcp-async-loop", daemon=True
        )
        self._loop_thread.start()

    def _run_async(self, coro):
        """Run a coroutine on the shared loop from a request thread"""
        if self._loop is None:
            raise RuntimeError("Event loop not started")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def serve(self, background: bool = True) -> None:
        """Start the MCP server"""
        self._start_event_loop()

        # Patch the MCP server's tools/list and tools/call methods.
        # The HTTP server is synchronous (one thread per request), so each
        # request submits its coroutine to the shared event loop and blocks
        # on the result — no per-request loop creation.
        def wrapped_tools_list(_meta=None):
            return self._run_async(self.proxy_tools_list())

        def wrapped_tools_call(name, arguments=None, _meta=None):
            return self._run_async(self.proxy_tools_call(name, arguments, _meta))

        self.mcp_server.registry.methods["tools/list"] = wrapped_tools_list
        self.mcp_server.registry.methods["tools/call"] = wrapped_tools_call

        # Start the server (always threaded to handle concurrent client requests)
        logger.info(f"Starting multi-session MCP server on {self.host}:{self.port}")
        self.mcp_server.serve(host=self.host, port=self.port, background=background, threaded=True)

    async def shutdown(self) -> None:
        """Shutdown the server and close all sessions"""
        logger.info("Shutting down multi-session MCP server")
        self.session_manager.shutdown()
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._loop_thread is not None:
                self._loop_thread.join(timeout=5)
                self._loop_thread = None
            self._loop.close()
            self._loop = None


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Multi-Session MCP Server for IDA Pro (Headless)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8745,
        help="Port to listen on (default: 8745)",
    )
    parser.add_argument(
        "--base-session-port",
        type=int,
        default=10000,
        help="Base port for session servers (default: 10000)",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=10,
        help="Maximum concurrent sessions (default: 10)",
    )
    parser.add_argument(
        "--file-load-timeout",
        type=int,
        default=3600,
        help="File load initialization timeout in seconds (default: 3600)",
    )
    parser.add_argument(
        "--idb-cache-dir",
        type=str,
        default=None,
        help="Directory for IDB cache files",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Enable unsafe functions (DANGEROUS)",
    )
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="Binary files to pre-load (optional)",
    )
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    # Create server
    server = MultiSessionMCPServer(
        host=args.host,
        port=args.port,
        base_session_port=args.base_session_port,
        max_sessions=args.max_sessions,
        file_load_timeout=args.file_load_timeout,
        idb_cache_dir=args.idb_cache_dir,
        unsafe=args.unsafe,
    )

    # Pre-load files if specified
    if args.files:
        logger.info(f"Pre-loading {len(args.files)} file(s)...")
        import asyncio
        last_session_id = None
        for file_path in args.files:
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                continue
            try:
                session_info = asyncio.run(server.session_manager.create_session(str(file_path)))
                last_session_id = session_info.id  # SessionInfo is a dataclass, not a dict
                logger.info(f"  Loaded: {file_path}")
            except Exception as e:
                logger.error(f"  Failed to load {file_path}: {e}")

        # Set the last loaded session as active
        if last_session_id:
            asyncio.run(server.session_manager.switch_session(last_session_id))
            logger.info(f"Active session set to: {last_session_id}")

    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        asyncio.run(server.shutdown())
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start server
    server.serve(background=False)


if __name__ == "__main__":
    main()
