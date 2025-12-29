# IDA MCP Server 使用说明

支持多文件分析

![image-20251229204640370](https://xipv6.oss-cn-hangzhou.aliyuncs.com/img/image-20251229204640370.png)

![image-20251229204647844](https://xipv6.oss-cn-hangzhou.aliyuncs.com/img/image-20251229204647844.png)

## 快速开始

### 1. 环境要求

- Python 3.11+
- IDA Pro 9.2 或更高版本（低版本也可以试试看我IDA7.7测试OK）
- uv 包管理器

### 2. 安装步骤

```bash
# 安装 uv
pip install uv

# 进入项目目录
cd ida-pro-mcp

# 安装依赖
uv sync

# 修改 IDA 路径
# 编辑 start_ida_mcp.bat，设置正确的 IDADIR 路径
```

### 3. 配置 IDA 路径

编辑 `ida-pro-mcp\start_ida_mcp.bat`，修改第 8 行：

```batch
set "IDADIR=E:\Tools\BinAny\IDA9.2"  # 改成你的 IDA 安装路径
```

### 4. 使用方式

#### 方式一：自动加载分析文件

1. 将要分析的 `.exe` 文件放入 `analyze\` 文件夹
2. 双击 `start.bat`
3. 服务器会自动加载所有文件并启动

#### 方式二：手动创建会话

1. 双击 `ida-pro-mcp\start_ida_mcp.bat` 启动空服务器
2. 通过 MCP 调用 `session_create` 创建分析会话

## MCP 配置

### Claude Desktop

编辑 Claude Desktop 配置文件，添加：

```json
{
  "mcpServers": {
    "ida-mcp": {
      "transport": {
        "type": "http",
        "url": "http://127.0.0.1:8746/mcp"
      }
    }
  }
}
```

### Cherry Studio

```json
{
  "mcpServers": {
    "ida-mcp": {
      "name": "IDA MCP 服务器",
      "baseUrl": "http://127.0.0.1:8746/mcp",
      "type": "http"
    }
  }
}
```

## 可用工具

### 会话管理

| 工具 | 说明 |
|------|------|
| `session_create` | 创建新的分析会话 |
| `session_list` | 列出所有会话 |
| `session_switch` | 切换活动会话 |
| `session_active` | 获取当前活动会话 |
| `session_close` | 关闭会话 |
| `session_status` | 获取会话管理器状态 |

### 分析工具

| 工具 | 说明 |
|------|------|
| `lookup_funcs` | 按名称查找函数 |
| `list_funcs` | 列出所有函数 |
| `decompile` | 反编译函数 |
| `disasm` | 反汇编函数 |
| `xrefs_to` | 获取交叉引用 |
| `callees` | 获取被调用函数 |
| `callers` | 获取调用者函数 |
| `strings` | 获取字符串列表 |
| `search` | 搜索模式 |
| `analyze_funcs` | 全面分析函数 |

### 使用示例

#### 创建会话并分析

```
1. session_list - 查看所有会话
2. session_switch - 切换到目标会话
3. lookup_funcs - 查找 main 函数
4. decompile - 反编译 main 函数
```

#### 参数示例

```json
// 查找函数
{"name": "lookup_funcs", "arguments": {"queries": "main"}}

// 反编译
{"name": "decompile", "arguments": {"addrs": "0x140001440"}}

// 列出函数
{"name": "list_funcs", "arguments": {"queries": {"count": 10, "offset": 0}}}
```

## 故障排除

### 端口被占用

`start.bat` 会自动清理端口，如需手动清理：

```batch
netstat -ano | findstr ":8746"
taskkill /F /PID <进程ID>
```

### IDB 文件被锁定

删除 `analyze\` 文件夹中的 `.id0`, `.id1`, `.id2` 等文件，重新分析。

### 会话创建失败

1. 检查 IDA 路径是否正确
2. 确认 IDA 版本 >= 9.2
3. 查看服务器日志输出

## 目录结构

```
IDA-MCP-Release/
├── analyze/           # 放待分析的文件
├── ida-pro-mcp/       # MCP 服务器
│   ├── .venv/        # 虚拟环境
│   └── src/
├── start.bat          # 一键启动（自动加载）
├── AVAILABLE_TOOLS.md # 工具列表
└── claude_desktop_config.json
```

## 技术信息

- **主服务器端口**: 8746
- **会话端口范围**: 10000+
- **协议**: MCP over HTTP (JSON-RPC 2.0)
- **最大并发会话**: 5
- **会话超时**: 3600 秒
