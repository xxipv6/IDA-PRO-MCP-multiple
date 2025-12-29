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
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from . import api_session

# Import session module directly to avoid triggering ida_mcp.__init__.py
import sys
from pathlib import Path
_ida_mcp_dir = str(Path(__file__).parent / "ida_mcp")
if _ida_mcp_dir not in sys.path:
    sys.path.insert(0, _ida_mcp_dir)

# Import session (no IDA dependencies)
import session as _session_module
init_session_manager = _session_module.init_session_manager
get_session_manager = _session_module.get_session_manager

# Import zeromcp (no IDA dependencies)
from zeromcp import McpServer, McpRpcRegistry, McpHttpRequestHandler, McpToolError

sys.path.pop(sys.path.index(_ida_mcp_dir))  # Clean up

logger = logging.getLogger(__name__)


class MultiSessionMCPServer:
    """MCP Server that supports multiple IDA Pro analysis sessions"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8745,
        base_session_port: int = 10000,
        max_sessions: int = 5,
        session_timeout: float = 3600,
        idb_cache_dir: Optional[str] = None,
        unsafe: bool = False,
    ):
        self.host = host
        self.port = port
        self.base_session_port = base_session_port
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self.unsafe = unsafe

        # Initialize session manager
        self.session_manager = init_session_manager(
            base_port=base_session_port,
            max_sessions=max_sessions,
            session_timeout=session_timeout,
            idb_cache_dir=idb_cache_dir,
        )

        # Create MCP server
        self.mcp_server = McpServer("ida-pro-mcp-multisession", version="2.0.0")

        # HTTP client for making requests to session servers
        self.http_client = httpx.AsyncClient(timeout=30.0)

        # Register session management tools
        self._register_session_tools()

        # Register proxy tools that forward to active session
        self._register_proxy_tools()

        logger.info(f"Multi-session MCP server initialized on {host}:{port}")
        logger.info(f"  Base session port: {base_session_port}")
        logger.info(f"  Max sessions: {max_sessions}")

    def _register_session_tools(self) -> None:
        """Register session management tools (direct implementation)"""
        # Session tools are handled directly in _handle_session_tool
        # No need to register here since we handle them in the proxy layer
        pass

    def _register_proxy_tools(self) -> None:
        """Register proxy tools that forward calls to the active session"""

        async def proxy_tool(
            tool_name: str,
            arguments: Optional[dict] = None,
            session_id: Optional[str] = None,
        ) -> dict:
            """Proxy a tool call to the appropriate session"""
            manager = get_session_manager()

            # Get the target session
            session = await manager.get_session_for_call(session_id)

            if not session:
                raise McpToolError(
                    f"No session available. Create a session with session_create first."
                )

            # Forward the request to the session's MCP server
            session_url = f"http://127.0.0.1:{session.port}/mcp"

            try:
                response = await self.http_client.post(
                    session_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": arguments,
                        },
                        "id": 1,
                    },
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPError as e:
                raise McpToolError(f"Failed to reach session {session.id}: {e}")

        # We'll dynamically register proxy tools based on what tools are available
        # This is done lazily when a session is created

    async def proxy_tools_list(self) -> dict:
        """Get the list of tools from the active session"""
        manager = get_session_manager()
        session = await manager.get_active_session()

        if not session:
            # Return only session management tools
            return {
                "tools": [
                    {
                        "name": "session_create",
                        "description": "Create a new analysis session",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file_path": {"type": "string"},
                                "auto_analysis": {"type": "boolean"},
                                "idb_path": {"type": "string"},
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
            }

        # Forward to active session
        session_url = f"http://127.0.0.1:{session.port}/mcp"

        try:
            response = await self.http_client.post(
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
                # Add session tools at the beginning
                session_tools = [
                    {
                        "name": "session_create",
                        "description": "Create a new analysis session",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file_path": {"type": "string"},
                                "auto_analysis": {"type": "boolean"},
                                "idb_path": {"type": "string"},
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
                result["result"]["tools"] = session_tools + result["result"]["tools"]

            return result.get("result", {"tools": []})
        except httpx.HTTPError as e:
            logger.error(f"Failed to get tools list from session: {e}")
            # Return predefined tools when session is unavailable
            return self._get_predefined_tools()

    def _get_predefined_tools(self) -> dict:
        """Return predefined IDA analysis tools"""
        session_tools = [
            {
                "name": "session_create",
                "description": "Create a new analysis session",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "auto_analysis": {"type": "boolean"},
                        "idb_path": {"type": "string"},
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

        analysis_tools = [
            {
                "name": "lookup_funcs",
                "description": "Look up functions by name/pattern",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "queries": {"type": "string"},
                    },
                    "required": ["queries"],
                },
            },
            {
                "name": "list_funcs",
                "description": "List all functions in the binary",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer"},
                        "count": {"type": "integer"},
                    },
                },
            },
            {
                "name": "decompile",
                "description": "Decompile a function at the given address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addrs": {"type": "string"},
                    },
                    "required": ["addrs"],
                },
            },
            {
                "name": "disasm",
                "description": "Disassemble a function",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addrs": {"type": "string"},
                    },
                },
            },
            {
                "name": "xrefs_to",
                "description": "Get cross-references to an address",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addrs": {"type": "string"},
                    },
                },
            },
            {
                "name": "callees",
                "description": "Get functions called by a function",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addrs": {"type": "string"},
                    },
                },
            },
            {
                "name": "callers",
                "description": "Get functions that call a function",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addrs": {"type": "string"},
                    },
                },
            },
            {
                "name": "strings",
                "description": "Get strings from the binary",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "queries": {"type": "object"},
                    },
                },
            },
            {
                "name": "search",
                "description": "Search for patterns in the binary",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "queries": {"type": "object"},
                    },
                },
            },
            {
                "name": "analyze_funcs",
                "description": "Analyze functions comprehensively",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "addrs": {"type": "string"},
                    },
                },
            },
        ]

        return {"tools": session_tools + analysis_tools}

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
        session = await manager.get_session_for_call(session_id)

        if not session:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "No active session. Use session_create to create a session first.",
                    }
                ],
                "isError": True,
            }

        session_url = f"http://127.0.0.1:{session.port}/mcp"

        try:
            response = await self.http_client.post(
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
            response.raise_for_status()
            # Extract the actual result from the JSON-RPC response
            # Session server returns: {"result": {"content": [...], "structuredContent": {...}, "isError": false}}
            # We need to return just the inner result, not wrap it again
            json_response = response.json()
            if "result" in json_response:
                return json_response["result"]
            return json_response
        except httpx.HTTPError as e:
            logger.error(f"Failed to call tool {name} on session {session.id}: {e}")
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Failed to reach session {session.id}: {e}",
                    }
                ],
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

    def serve(self, background: bool = True) -> None:
        """Start the MCP server"""
        # Patch the MCP server's tools/list and tools/call methods
        # Note: The HTTP server is synchronous, so we need to run async code in an event loop
        def wrapped_tools_list(_meta=None):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.proxy_tools_list())
            finally:
                loop.close()

        def wrapped_tools_call(name, arguments=None, _meta=None):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.proxy_tools_call(name, arguments, _meta))
            finally:
                loop.close()

        self.mcp_server.registry.methods["tools/list"] = wrapped_tools_list
        self.mcp_server.registry.methods["tools/call"] = wrapped_tools_call

        # Start the server
        logger.info(f"Starting multi-session MCP server on {self.host}:{self.port}")
        self.mcp_server.serve(host=self.host, port=self.port, background=background)

    async def shutdown(self) -> None:
        """Shutdown the server and close all sessions"""
        logger.info("Shutting down multi-session MCP server")
        await self.http_client.aclose()
        self.session_manager.shutdown()


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
        default=5,
        help="Maximum concurrent sessions (default: 5)",
    )
    parser.add_argument(
        "--session-timeout",
        type=int,
        default=3600,
        help="Session idle timeout in seconds (default: 3600)",
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
        session_timeout=args.session_timeout,
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
