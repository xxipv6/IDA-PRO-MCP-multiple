"""Load analysis tool schemas without a running IDA instance.

The multiserver proxy must serve the full tool list even when no session
is active (e.g. a no_preload start, or before session_create). Tool
schemas are generated from the @tool-decorated functions in
ida_pro_mcp.ida_mcp, but importing that package requires the ida_*
modules, which only exist inside IDA/idalib.

This module stubs the ida_* modules so the package can be imported in a
plain Python process and the schemas read from the registry. The stubs
exist only to satisfy imports — tool functions are never called here.
"""

import logging
import sys
import types
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec
from typing import Any
from unittest.mock import MagicMock

logger = logging.getLogger(__name__)


class _StubModule(types.ModuleType):
    """Module that fabricates a MagicMock for any attribute access."""

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        value = MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, value)
        return value


def _create_stub_module(fullname: str) -> _StubModule:
    mod = _StubModule(fullname)
    if fullname == "idaapi":
        # sync.py does: map(int, idaapi.get_kernel_version().split("."))
        mod.get_kernel_version = lambda: "9.2"
        # Real MFF_* constants so sync.py's safety-mode check passes, and a
        # pass-through execute_sync so the @idasync-wrapped config helpers in
        # http.py (invoked at import time) run their body in-process.
        mod.MFF_FAST = 0
        mod.MFF_READ = 1
        mod.MFF_WRITE = 2
        mod.execute_sync = lambda fn, _mode: fn()
    elif fullname == "ida_kernwin":
        # sync.py: class IDASafety(IntEnum) requires real int values
        mod.MFF_FAST = 0
        mod.MFF_READ = 1
        mod.MFF_WRITE = 2
    elif fullname == "ida_netnode":
        # http.py reads tool-enable config at import time; behave like a
        # fresh IDB (nothing stored) so every tool stays enabled.
        node = MagicMock(name="ida_netnode.netnode()")
        node.getblob.return_value = None
        mod.netnode = lambda *a, **k: node
    return mod


class _IdaStubImporter(MetaPathFinder, Loader):
    """Imports `ida_*`/`idaapi`/`idautils`/`idc` modules as stubs.

    Installed on sys.meta_path only while ida_pro_mcp.ida_mcp is being
    imported for schema extraction. `ida_pro_mcp` and `idapro` are
    excluded — the former is the real package doing the importing, the
    latter is the idalib bootstrap.
    """

    _EXCLUDED_ROOTS = ("ida_pro_mcp", "idapro")

    def find_spec(self, fullname, path=None, target=None):
        root = fullname.partition(".")[0]
        if root in self._EXCLUDED_ROOTS:
            return None
        if root in ("idaapi", "idautils", "idc") or root.startswith("ida_"):
            return ModuleSpec(fullname, self)
        return None

    def create_module(self, spec):
        return _create_stub_module(spec.name)

    def exec_module(self, module):
        pass


def load_analysis_tools() -> list[dict]:
    """Import ida_pro_mcp.ida_mcp with stubbed ida_* modules and return
    the MCP tool schema for every registered analysis tool."""
    importer = _IdaStubImporter()
    sys.meta_path.insert(0, importer)
    try:
        # Importing the package registers all @tool functions on MCP_SERVER
        from .ida_mcp.rpc import MCP_SERVER

        tools_list = MCP_SERVER.registry.methods["tools/list"]
        result = tools_list()
        return list(result.get("tools", []))
    finally:
        sys.meta_path.remove(importer)
