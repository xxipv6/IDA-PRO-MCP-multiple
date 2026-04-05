"""Session Management API - MCP Tools for managing analysis sessions

This module provides MCP tools for creating, listing, switching, and closing
IDA Pro analysis sessions when running in multi-session mode.

NOTE: This module does NOT use @tool decorator or import from ida_mcp.rpc
because it runs in the main process, not within IDA. The tool registration
is handled by MultiSessionMCPServer directly.
"""

from importlib import util
from pathlib import Path
from typing import Annotated, Optional, Any


def _load_session_module():
    session_path = Path(__file__).parent / "ida_mcp" / "session.py"
    spec = util.spec_from_file_location("ida_pro_mcp_session", session_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to load session module from {session_path}")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


session = _load_session_module()
get_session_manager = session.get_session_manager
SessionInfo = session.SessionInfo


# =============================================================================
# Session Management Tools (Plain async functions, no decorators)
# =============================================================================


async def session_create(
    file_path: Annotated[str, "Path to the binary file to analyze"],
    auto_analysis: Annotated[bool, "Whether to run auto-analysis (default: true)"] = True,
    metadata: Annotated[Optional[dict[str, Any]], "Optional metadata to attach to the session"] = None,
) -> dict:
    """Create a new analysis session for a binary file

    Creates a new IDA Pro analysis session in a separate process.
    The session will run auto-analysis and be ready for queries.

    Args:
        file_path: Path to the binary file to analyze
        auto_analysis: Whether to run auto-analysis (default: true)
        metadata: Optional metadata to attach to the session

    Returns:
        Session information including id, status, port, etc.

    Example:
        session_create("/path/to/binary.exe")
        -> {"id": "abc123", "status": "ready", "port": 10001, ...}
    """
    manager = get_session_manager()
    info = await manager.create_session(
        file_path=file_path,
        auto_analysis=auto_analysis,
        metadata=metadata or {},
    )
    return info.to_dict()


async def session_list() -> list[dict]:
    """List all analysis sessions

    Returns information about all currently active sessions including
    their status, file paths, and ports.

    Returns:
        List of session information dictionaries

    Example:
        session_list()
        -> [
            {"id": "abc123", "file_path": "/path/binary1.exe", "status": "ready", ...},
            {"id": "def456", "file_path": "/path/binary2.dll", "status": "ready", ...}
        ]
    """
    manager = get_session_manager()
    sessions = await manager.list_sessions()
    return [s.to_dict() for s in sessions]


async def session_get(
    session_id: Annotated[str, "Session ID to get information for"],
) -> Optional[dict]:
    """Get detailed information about a specific session

    Args:
        session_id: The ID of the session to query

    Returns:
        Session information dictionary, or None if session not found

    Example:
        session_get("abc123")
        -> {"id": "abc123", "file_path": "/path/binary.exe", "status": "ready", ...}
    """
    manager = get_session_manager()
    info = await manager.get_session(session_id)
    return info.to_dict() if info else None


async def session_switch(
    session_id: Annotated[str, "Session ID to switch to"],
) -> dict:
    """Switch the active session for tool calls

    Sets the specified session as the active session. All subsequent
    tool calls without an explicit session_id parameter will use this session.

    Args:
        session_id: The ID of the session to switch to

    Returns:
        Success status and current active session info

    Example:
        session_switch("abc123")
        -> {"success": true, "active_session": "abc123"}
    """
    manager = get_session_manager()
    success = await manager.switch_session(session_id)

    if not success:
        return {
            "success": False,
            "error": f"Session {session_id} not found",
            "active_session": None,
        }

    # Get session info
    info = await manager.get_session(session_id)
    return {
        "success": True,
        "active_session": session_id,
        "session_info": info.to_dict() if info else None,
    }


async def session_close(
    session_id: Annotated[str, "Session ID to close"],
) -> dict:
    """Close an analysis session

    Closes the specified session and releases its resources.
    The IDA Pro process will be terminated.

    Args:
        session_id: The ID of the session to close

    Returns:
        Success status

    Example:
        session_close("abc123")
        -> {"success": true, "closed_session": "abc123"}
    """
    manager = get_session_manager()
    success = await manager.close_session(session_id)

    if not success:
        return {
            "success": False,
            "error": f"Session {session_id} not found",
            "closed_session": None,
        }

    return {
        "success": True,
        "closed_session": session_id,
    }


async def session_active() -> Optional[dict]:
    """Get the currently active session

    Returns information about the currently active session.
    This is the session that will be used for tool calls without
    an explicit session_id parameter.

    Returns:
        Active session information, or None if no session is active

    Example:
        session_active()
        -> {"id": "abc123", "file_path": "/path/binary.exe", "status": "ready", ...}
    """
    manager = get_session_manager()
    session = await manager.get_active_session()

    if session is None:
        return None

    return session.get_info().to_dict()


async def session_status() -> dict:
    """Get overall session manager status

    Returns statistics about the session manager including
    the number of active sessions and configuration limits.

    Returns:
        Session manager status information

    Example:
        session_status()
        -> {
            "total_sessions": 2,
            "ready_sessions": 2,
            "max_sessions": 10,
            "active_session": "abc123",
            "base_port": 10000
        }
    """
    manager = get_session_manager()
    sessions = await manager.list_sessions()

    ready_count = sum(1 for s in sessions if s.status.value == "ready")

    return {
        "total_sessions": len(sessions),
        "ready_sessions": ready_count,
        "max_sessions": manager.max_sessions,
        "active_session": manager.active_session_id,
        "base_port": manager.base_port,
        "idb_cache_dir": str(manager.idb_cache_dir) if manager.idb_cache_dir else None,
    }
