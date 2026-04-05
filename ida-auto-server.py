#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA MCP 自动分析服务器
自动扫描 analyze 文件夹，加载所有可执行文件
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import httpx
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent

# Windows终端编码修复
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class Config:
    """配置管理"""

    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.data = self.load()

    def load(self) -> dict:
        """加载配置文件"""
        if not self.config_path.exists():
            logger.warning(f"配置文件不存在: {self.config_path}")
            return self.get_default_config()

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
            return self.get_default_config()

    def get_default_config(self) -> dict:
        """获取默认配置"""
        return {
            "server": {
                "host": "127.0.0.1",
                "port": 8745,
                "base_session_port": 10000,
                "max_sessions": 10
            },
            "analysis": {
                "scan_folder": "analyze",
                "file_patterns": ["*.exe", "*.dll", "*.sys", "*.elf", "*.so"],
                "auto_load": True,
                "recursive": False
            },
            "ida": {
                "idadir": "E:\\Tools\\BinAny\\IDA9.2",
                "idb_cache_dir": "idb_cache"
            }
        }

    def get(self, *keys, default=None):
        """获取配置值"""
        data = self.data
        for key in keys:
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                return default
        return data


class FileScanner:
    """文件扫描器"""

    def __init__(self, config: Config):
        self.config = config
        self.work_dir = Path(__file__).parent
        self.scan_folder = self.work_dir / config.get("analysis", "scan_folder", default="analyze")

    def scan(self) -> List[Path]:
        """扫描文件夹，收集可执行文件"""
        patterns = self.config.get("analysis", "file_patterns", default=["*.exe", "*.dll"])
        recursive = self.config.get("analysis", "recursive", default=False)

        if not self.scan_folder.exists():
            logger.warning(f"扫描文件夹不存在: {self.scan_folder}")
            self.scan_folder.mkdir(parents=True, exist_ok=True)
            logger.info(f"已创建文件夹: {self.scan_folder}")
            return []

        files = []
        for pattern in patterns:
            if recursive:
                files.extend(self.scan_folder.rglob(pattern))
            else:
                files.extend(self.scan_folder.glob(pattern))

        # 去重并排序
        files = sorted(set(files))

        logger.info(f"扫描完成: 找到 {len(files)} 个文件")
        return files

    def watch(self, callback):
        """监听文件夹变化"""
        class NewFileHandler(FileSystemEventHandler):
            def __init__(self, patterns, cb):
                self.patterns = patterns
                self.callback = cb

            def on_created(self, event):
                if not event.is_directory:
                    path = Path(event.src_path)
                    for pattern in self.patterns:
                        if path.match(pattern):
                            logger.info(f"检测到新文件: {path.name}")
                            asyncio.create_task(self.callback(path))
                            break

        observer = Observer()
        patterns = self.config.get("analysis", "file_patterns", default=["*.exe"])
        handler = NewFileHandler(patterns, callback)
        observer.schedule(handler, str(self.scan_folder), recursive=False)
        observer.start()
        logger.info(f"开始监听文件夹: {self.scan_folder}")
        return observer


class IDAMCPServer:
    """IDA MCP 服务器客户端"""

    def __init__(self, config: Config):
        self.config = config
        self.host = config.get("server", "host", default="127.0.0.1")
        self.port = config.get("server", "port", default=8745)
        self.base_url = f"http://{self.host}:{self.port}/mcp"
        self.client = None
        self.sessions = {}  # file_path -> session_id

    async def __aenter__(self):
        self.client = httpx.AsyncClient(timeout=120.0)
        return self

    async def __aexit__(self, *args):
        if self.client:
            await self.client.aclose()

    def _rpc_call(self, tool_name: str, arguments: dict = None) -> dict:
        """构造RPC调用"""
        return {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            },
            "id": 1
        }

    async def call_tool(self, tool_name: str, arguments: dict = None) -> dict:
        """调用MCP工具"""
        payload = self._rpc_call(tool_name, arguments)

        try:
            response = await self.client.post(self.base_url, json=payload)
            response.raise_for_status()
            result = response.json()

            # 处理嵌套的result结构
            if "result" in result:
                inner = result["result"]
                if "result" in inner:
                    return inner["result"]
                elif "structuredContent" in inner:
                    return inner["structuredContent"]
                return inner
            return result

        except Exception as e:
            logger.error(f"工具调用失败 {tool_name}: {e}")
            return {"error": str(e)}

    async def check_server(self) -> bool:
        """检查服务器是否运行"""
        try:
            # 尝试调用 session_list 来检查服务器是否运行
            result = await self.call_tool("session_list")
            return True
        except Exception as e:
            logger.debug(f"Server check failed: {e}")
            return False

    async def list_sessions(self) -> List[dict]:
        """列出所有会话"""
        result = await self.call_tool("session_list")
        if isinstance(result, list):
            return result
        return []

    async def create_session(self, file_path: Path) -> Optional[str]:
        """创建分析会话"""
        abs_path = file_path.resolve()

        # 检查是否已存在会话
        if str(abs_path) in self.sessions:
            return self.sessions[str(abs_path)]

        logger.info(f"  加载: {file_path.name}")
        result = await self.call_tool("session_create", {"file_path": str(abs_path)})

        if isinstance(result, dict):
            session_id = result.get("id")
            if session_id:
                self.sessions[str(abs_path)] = session_id
                logger.info(f"    [OK] 会话: {session_id}")
                return session_id
            else:
                error = result.get("error_message", "未知错误")
                logger.error(f"    [ERROR] {error}")
        else:
            logger.error(f"    [ERROR] 响应格式错误")

        return None

    async def switch_session(self, session_id: str) -> bool:
        """切换活动会话"""
        result = await self.call_tool("session_switch", {"session_id": session_id})
        if isinstance(result, dict) and result.get("success"):
            return True
        return False

    async def decompile_main(self) -> Optional[str]:
        """反编译main函数"""
        result = await self.call_tool("lookup_funcs", {"queries": "main"})

        # 处理不同的响应格式
        main_func = None
        if isinstance(result, list) and len(result) > 0:
            if "fn" in result[0]:
                main_func = result[0]["fn"]
            elif isinstance(result[0], dict) and "structuredContent" in result[0]:
                inner = result[0]["structuredContent"]
                if isinstance(inner, list) and len(inner) > 0 and "fn" in inner[0]:
                    main_func = inner[0]["fn"]

        if not main_func or not main_func.get("addr"):
            logger.warning("未找到main函数")
            return None

        addr = main_func["addr"]
        logger.info(f"  main地址: {addr}")

        result = await self.call_tool("decompile", {"addrs": addr})

        if isinstance(result, dict) and "structuredContent" in result:
            code = result["structuredContent"]["result"][0]["code"]
            return code
        elif isinstance(result, list) and len(result) > 0:
            if "code" in result[0]:
                return result[0]["code"]
            elif "structuredContent" in result[0]:
                inner = result[0]["structuredContent"]
                if isinstance(inner, dict) and "result" in inner:
                    return inner["result"][0]["code"]

        return None


class AutoAnalyzer:
    """自动分析器"""

    def __init__(self, config: Config):
        self.config = config
        self.scanner = FileScanner(config)
        self.server = IDAMCPServer(config)
        self.running = False

    async def load_files(self, files: List[Path]) -> int:
        """加载所有文件"""
        if not files:
            logger.warning("没有找到可执行文件")
            return 0

        print("\n[自动加载]")
        print("=" * 50)

        success_count = 0
        for i, file_path in enumerate(files, 1):
            print(f"\n[{i}/{len(files)}]", end=" ")
            session_id = await self.server.create_session(file_path)
            if session_id:
                success_count += 1

        print("\n" + "=" * 50)
        logger.info(f"加载完成: {success_count}/{len(files)} 成功")
        return success_count

    async def analyze_all_main(self):
        """分析所有会话的main函数"""
        sessions = await self.server.list_sessions()

        if not sessions:
            logger.warning("没有活动的会话")
            return

        print("\n[分析main函数]")
        print("=" * 50)

        for session in sessions:
            file_name = Path(session.get("file_path", "")).name
            session_id = session.get("id")
            status = session.get("status", "unknown")

            if status != "ready":
                logger.info(f"[{file_name}] 跳过 (状态: {status})")
                continue

            print(f"\n[{file_name}]")
            await self.server.switch_session(session_id)
            code = await self.server.decompile_main()
            if code:
                print("-" * 50)
                print(code)
                print("-" * 50)

    async def run(self):
        """运行自动分析服务器"""
        self.running = True

        # 显示启动信息
        print("\n" + "=" * 50)
        print("IDA MCP 自动分析服务器")
        print("=" * 50)
        print(f"端口: {self.config.get('server', 'port')}")
        print(f"扫描文件夹: {self.config.get('analysis', 'scan_folder')}")
        print("=" * 50)

        async with self.server:
            # 检查服务器连接
            if not await self.server.check_server():
                logger.error("MCP服务器未运行！")
                logger.info("请先在 config.toml 中设置 no_preload = true，然后启动: python start.py")
                return

            logger.info("已连接到MCP服务器")

            # 扫描文件
            print("\n[扫描文件]")
            files = self.scanner.scan()

            # 加载文件
            await self.load_files(files)

            # 显示状态
            await self.show_status()

            # 保持运行
            print("\n服务器运行中...")
            print("命令: --list, --reload, --main, --quit\n")

            # 简单命令循环
            while self.running:
                await asyncio.sleep(1)

    async def show_status(self):
        """显示服务器状态"""
        sessions = await self.server.list_sessions()

        print("\n[会话状态]")
        print("-" * 50)
        for s in sessions:
            file_name = Path(s.get("file_path", "")).name
            sid = s.get("id", "N/A")[:8]
            status = s.get("status", "unknown")
            print(f"  [{sid}] {file_name} - {status}")
        print("-" * 50)

    async def reload_files(self):
        """重新扫描并加载新文件"""
        print("\n[重新扫描]")
        files = self.scanner.scan()
        await self.load_files(files)
        await self.show_status()


async def main():
    """主函数"""
    # 加载配置
    config = Config("config.json")

    # 创建分析器
    analyzer = AutoAnalyzer(config)

    # 运行
    try:
        await analyzer.run()
    except KeyboardInterrupt:
        print("\n\n[退出]")
        analyzer.running = False
    except Exception as e:
        logger.error(f"运行错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
