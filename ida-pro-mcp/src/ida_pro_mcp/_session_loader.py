from importlib import util
from pathlib import Path
import sys


MODULE_NAME = "ida_pro_mcp_session"


def load_session_module():
    module = sys.modules.get(MODULE_NAME)
    if module is not None:
        return module

    session_path = Path(__file__).parent / "ida_mcp" / "session.py"
    spec = util.spec_from_file_location(MODULE_NAME, session_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to load session module from {session_path}")

    module = util.module_from_spec(spec)
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module
