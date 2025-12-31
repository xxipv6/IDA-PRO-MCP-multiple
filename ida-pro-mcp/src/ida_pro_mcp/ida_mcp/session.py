"""Session Management for Multi-Instance IDA Pro MCP

This module provides the ability to manage multiple IDA Pro analysis sessions
simultaneously, each analyzing a different binary file.
"""

import asyncio
import ctypes
import logging
import multiprocessing
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Status of an analysis session"""
    CREATING = "creating"
    LOADING = "loading"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    CLOSED = "closed"


@dataclass
class SessionInfo:
    """Information about a session"""
    id: str
    file_path: str
    status: SessionStatus
    created_at: datetime
    port: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "port": self.port,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


class Session:
    """A single IDA Pro analysis session

    Each session wraps an IDALib instance running in a separate process
    to ensure isolation and allow concurrent analysis.
    """

    def __init__(
        self,
        session_id: str,
        file_path: str,
        port: int,
        idb_path: Optional[str] = None,
        auto_analysis: bool = True,
    ):
        self.id = session_id
        self.file_path = str(file_path)
        self.port = port
        self.idb_path = idb_path
        self.auto_analysis = auto_analysis
        self.status = SessionStatus.CREATING
        self.created_at = datetime.now()
        self.error_message: Optional[str] = None
        self.metadata: Dict[str, Any] = {}

        # Process management
        self._process: Optional[subprocess.Popen] = None
        self._ready_event_path: Optional[Path] = None
        self._lock = threading.Lock()

        # Last activity timestamp (for timeout management)
        self._last_activity = time.time()

    @property
    def is_ready(self) -> bool:
        """Check if session is ready for operations"""
        return self.status == SessionStatus.READY

    @property
    def is_closed(self) -> bool:
        """Check if session is closed"""
        return self.status == SessionStatus.CLOSED

    @property
    def is_alive(self) -> bool:
        """Check if the session process is still running"""
        if self._process is None:
            return False
        return self._process.poll() is None

    def start(self) -> None:
        """Start the IDA Pro analysis process"""
        with self._lock:
            if self._process is not None:
                raise RuntimeError(f"Session {self.id} already has a running process")

            self.status = SessionStatus.LOADING
            logger.info(f"Starting session {self.id} for {self.file_path}")

            # Create a ready file for signaling
            import tempfile
            self._ready_event_path = Path(tempfile.gettempdir()) / f"ida_mcp_{self.id}_ready"

            # Build command to run the session worker
            worker_script = Path(__file__).parent / "session_worker.py"
            cmd = [
                sys.executable,
                str(worker_script),
                self.file_path,
                "--port", str(self.port),
                "--ready-file", str(self._ready_event_path),
            ]
            if self.idb_path:
                cmd.extend(["--idb-path", self.idb_path])
            if not self.auto_analysis:
                cmd.append("--no-auto-analysis")

            # Start the subprocess
            # Note: We don't capture stdout/stderr so logs go to console
            self._process = subprocess.Popen(
                cmd,
                stdout=None,  # Inherit stdout from parent
                stderr=None,  # Inherit stderr from parent
                text=True,
            )

            # Wait for the process to signal ready (with timeout)
            start_time = time.time()
            timeout = 300  # 5 minutes
            while time.time() - start_time < timeout:
                if self._ready_event_path.exists():
                    # Ready file exists, session is ready
                    self._ready_event_path.unlink()
                    break
                if self._process.poll() is not None:
                    # Process has terminated
                    self.status = SessionStatus.ERROR
                    self.error_message = "IDA process terminated unexpectedly"
                    logger.error(f"Session {self.id} process terminated unexpectedly")
                    raise RuntimeError(f"Session {self.id} process terminated unexpectedly")
                time.sleep(0.1)
            else:
                # Timeout
                self.status = SessionStatus.ERROR
                self.error_message = "Timeout waiting for IDA to initialize"
                logger.error(f"Session {self.id} failed to initialize: timeout")
                if self._process:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                raise RuntimeError(f"Session {self.id} initialization timeout")

            # Double-check process is still running
            if self._process.poll() is not None:
                self.status = SessionStatus.ERROR
                self.error_message = "IDA process terminated unexpectedly after ready"
                raise RuntimeError(f"Session {self.id} process terminated after ready")

            self.status = SessionStatus.READY
            logger.info(f"Session {self.id} ready on port {self.port}")

    def close(self) -> None:
        """Close the session and terminate the IDA process"""
        with self._lock:
            if self.status == SessionStatus.CLOSED:
                return

            logger.info(f"Closing session {self.id}")
            self.status = SessionStatus.CLOSED

            if self._process:
                if self._process.poll() is None:  # Process is still running
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Force killing session {self.id}")
                        self._process.kill()
                        self._process.wait(timeout=5)
                self._process = None

            # Clean up ready file if it exists
            if self._ready_event_path and self._ready_event_path.exists():
                self._ready_event_path.unlink()

    def get_info(self) -> SessionInfo:
        """Get session information"""
        return SessionInfo(
            id=self.id,
            file_path=self.file_path,
            status=self.status,
            created_at=self.created_at,
            port=self.port,
            error_message=self.error_message,
            metadata=self.metadata.copy(),
        )

    def update_activity(self) -> None:
        """Update last activity timestamp"""
        self._last_activity = time.time()

    def get_idle_time(self) -> float:
        """Get idle time in seconds"""
        return time.time() - self._last_activity


class SessionManager:
    """Manages multiple IDA Pro analysis sessions"""

    def __init__(
        self,
        base_port: int = 10000,
        max_sessions: int = 5,
        session_timeout: float = 3600,
        idb_cache_dir: Optional[str] = None,
    ):
        self.base_port = base_port
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self.idb_cache_dir = Path(idb_cache_dir) if idb_cache_dir else None

        self._sessions: Dict[str, Session] = {}
        self._port_allocator: set = set()
        self._lock = threading.Lock()
        self._active_session_id: Optional[str] = None

        # Create IDB cache directory if specified
        if self.idb_cache_dir:
            self.idb_cache_dir.mkdir(parents=True, exist_ok=True)

        # Start background cleanup task
        self._stop_cleanup = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _allocate_port(self) -> int:
        """Allocate a port for a new session"""
        for offset in range(self.max_sessions * 2):  # Allow some port gaps
            port = self.base_port + offset
            if port not in self._port_allocator:
                self._port_allocator.add(port)
                return port
        raise RuntimeError("No available ports for new session")

    def _release_port(self, port: int) -> None:
        """Release a port"""
        self._port_allocator.discard(port)

    def _cleanup_loop(self) -> None:
        """Background loop to clean up idle sessions"""
        while not self._stop_cleanup.is_set():
            try:
                time.sleep(60)  # Check every minute
                self._cleanup_idle_sessions()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    def _cleanup_idle_sessions(self) -> None:
        """Close sessions that have been idle for too long or terminated"""
        with self._lock:
            for session_id, session in list(self._sessions.items()):
                # Check if process has terminated
                if session.status == SessionStatus.READY and not session.is_alive:
                    logger.warning(
                        f"Session {session_id} process terminated unexpectedly, cleaning up..."
                    )
                    session.status = SessionStatus.ERROR
                    session.error_message = "Process terminated unexpectedly"
                    self._close_session_unlocked(session_id)
                    continue

                # Check idle timeout
                if session.status == SessionStatus.READY:
                    idle_time = session.get_idle_time()
                    if idle_time > self.session_timeout:
                        logger.info(
                            f"Closing idle session {session_id} "
                            f"(idle for {idle_time:.0f}s)"
                        )
                        self._close_session_unlocked(session_id)

    def _close_session_unlocked(self, session_id: str) -> None:
        """Close a session (caller must hold lock)"""
        session = self._sessions.pop(session_id, None)
        if session:
            if self._active_session_id == session_id:
                self._active_session_id = None
            session.close()
            self._release_port(session.port)

    async def create_session(
        self,
        file_path: str,
        idb_path: Optional[str] = None,
        auto_analysis: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SessionInfo:
        """Create a new analysis session

        Args:
            file_path: Path to the binary file to analyze
            idb_path: Optional path for the IDB file
            auto_analysis: Whether to run auto analysis
            metadata: Optional metadata to attach to the session

        Returns:
            SessionInfo: Information about the created session

        Raises:
            FileNotFoundError: If the input file doesn't exist
            RuntimeError: If max sessions reached or creation fails
        """
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            raise FileNotFoundError(f"Input file not found: {file_path}")

        with self._lock:
            if len(self._sessions) >= self.max_sessions:
                # Try to close an idle session first
                closed = False
                for session_id, session in self._sessions.items():
                    if session.status == SessionStatus.READY:
                        idle_time = session.get_idle_time()
                        if idle_time > 300:  # 5 minutes minimum
                            self._close_session_unlocked(session_id)
                            closed = True
                            break

                if not closed or len(self._sessions) >= self.max_sessions:
                    raise RuntimeError(
                        f"Maximum sessions ({self.max_sessions}) reached. "
                        f"Close an existing session first."
                    )

            # Allocate port and create session
            port = self._allocate_port()
            session_id = str(uuid.uuid4())[:8]

            # Generate IDB path if not provided
            if idb_path is None and self.idb_cache_dir:
                idb_path = str(self.idb_cache_dir / f"{session_id}_{file_path_obj.name}.idb")

            session = Session(
                session_id=session_id,
                file_path=str(file_path_obj),
                port=port,
                idb_path=idb_path,
                auto_analysis=auto_analysis,
            )

            if metadata:
                session.metadata.update(metadata)

            self._sessions[session_id] = session

            # Set as active if it's the first session
            if self._active_session_id is None:
                self._active_session_id = session_id

        # Start the session outside the lock (may take time)
        try:
            session.start()
        except Exception as e:
            # Clean up on failure
            with self._lock:
                self._close_session_unlocked(session_id)
            raise

        return session.get_info()

    async def list_sessions(self) -> list[SessionInfo]:
        """List all sessions"""
        with self._lock:
            return [s.get_info() for s in self._sessions.values()]

    async def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """Get information about a specific session"""
        with self._lock:
            session = self._sessions.get(session_id)
            return session.get_info() if session else None

    async def switch_session(self, session_id: str) -> bool:
        """Switch the active session

        Args:
            session_id: ID of the session to switch to

        Returns:
            True if successful, False if session not found

        Raises:
            RuntimeError: If the session is not ready
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            if session.status != SessionStatus.READY:
                raise RuntimeError(
                    f"Cannot switch to session {session_id}: "
                    f"status is {session.status.value}"
                )

            self._active_session_id = session_id
            session.update_activity()
            return True

    async def get_active_session(self) -> Optional[Session]:
        """Get the currently active session"""
        with self._lock:
            if self._active_session_id is None:
                return None
            session = self._sessions.get(self._active_session_id)
            if session:
                session.update_activity()
            return session

    async def get_session_for_call(self, session_id: Optional[str]) -> Session:
        """Get a session for a tool call

        Args:
            session_id: Optional session ID, uses active session if None

        Returns:
            The Session object

        Raises:
            RuntimeError: If no session is available or not ready
        """
        if session_id:
            with self._lock:
                session = self._sessions.get(session_id)
                if not session:
                    raise RuntimeError(f"Session {session_id} not found")
                if session.status != SessionStatus.READY:
                    raise RuntimeError(
                        f"Session {session_id} is not ready (status: {session.status.value})"
                    )
                # Check if process is still alive
                if not session.is_alive:
                    raise RuntimeError(
                        f"Session {session_id} process has terminated unexpectedly"
                    )
                session.update_activity()
                return session
        else:
            session = await self.get_active_session()
            if not session:
                raise RuntimeError("No active session. Use session_create or session_switch first.")
            if session.status != SessionStatus.READY:
                raise RuntimeError(
                    f"Active session is not ready (status: {session.status.value})"
                )
            # Check if process is still alive
            if not session.is_alive:
                raise RuntimeError(
                    f"Active session {session.id} process has terminated unexpectedly"
                )
            return session

    async def close_session(self, session_id: str) -> bool:
        """Close a specific session

        Args:
            session_id: ID of the session to close

        Returns:
            True if session was closed, False if not found
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            self._close_session_unlocked(session_id)
            return True

    async def close_all(self) -> None:
        """Close all sessions"""
        with self._lock:
            for session_id in list(self._sessions.keys()):
                self._close_session_unlocked(session_id)

    def shutdown(self) -> None:
        """Shutdown the session manager"""
        logger.info("Shutting down session manager")
        self._stop_cleanup.set()

        # Close all sessions
        for session in list(self._sessions.values()):
            session.close()

        self._sessions.clear()

        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the global session manager instance"""
    global _session_manager
    if _session_manager is None:
        raise RuntimeError("Session manager not initialized. Call init_session_manager() first.")
    return _session_manager


def init_session_manager(
    base_port: int = 10000,
    max_sessions: int = 5,
    session_timeout: float = 3600,
    idb_cache_dir: Optional[str] = None,
) -> SessionManager:
    """Initialize the global session manager"""
    global _session_manager
    if _session_manager is not None:
        raise RuntimeError("Session manager already initialized")
    _session_manager = SessionManager(
        base_port=base_port,
        max_sessions=max_sessions,
        session_timeout=session_timeout,
        idb_cache_dir=idb_cache_dir,
    )
    return _session_manager
