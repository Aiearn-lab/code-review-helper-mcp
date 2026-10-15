# code-review-helper-mcp · 代码审查辅助工具

> 知微工作室 · Zhiwei Studio｜2026-10-15｜v1.0.0｜Node 18+，MIT

一个轻量 MCP server，把代码审查交付从 30 分钟压到 5 分钟。两个工具：**scan_code**（规则扫描）+ **gen_report**（生成 Markdown 审查报告初稿）。零第三方依赖。

## 安装

```bash
cd code-review-helper-mcp
npm install
```

验证安装：`node --check index.js`｜运行自测：`node test.js`

## 接入（MCP 客户端配置）

```json
{
  "mcpServers": {
    "code-review-helper": {
      "command": "node",
      "args": ["/你的绝对路径/code-review-helper-mcp/index.js"]
    }
  }
}
```

## 两个工具

### `scan_code`

扫描代码中的安全问题和坏味道。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `code` | `string` | 是 | 要扫描的代码文本 |
| `filename` | `string` | 否 | 文件名（用于语言推断和报告展示） |

**检测规则：**

| ID | 严重级 | 检测项 |
|---|---|---|
| SEC001 | critical | eval() 远程代码执行 |
| SEC002 | critical | exec() 远程代码执行 |
| SEC003 | critical | pickle.load() 反序列化 RCE |
| SEC004 | high | yaml.load() 未指定 Loader |
| SEC005 | critical | SQL 字符串拼接/注入 |
| SEC006 | critical | shell=True 命令注入 |
| SEC007 | critical | 硬编码 API 密钥（sk-/api_key=） |
| SEC008 | high | 硬编码密码（password=） |
| SEC009 | high | assert 用于数据校验 |
| SMELL001 | medium | 裸 except |
| SMELL002 | medium | 可变默认参数 |
| SMELL003 | medium | global 滥用 |
| SMELL004 | low | 超长函数（>80行） |
| SMELL005 | low | 重复代码块 |

### `gen_report`

把 scan_code 的结果生成 Markdown 审查报告。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `scanResult` | `object` | 是 | scan_code 的完整返回结果 |

**报告结构：** 概述 → 发现汇总表 → 详细发现 → 安全专项 → 验证记录 → 修订说明

**调用示例（对 agent 说）：**

> 帮我审查这段 Python 代码：（粘贴代码）

## 严重级定义

| 级 | 含义 |
|---|---|
| **critical** | 可被直接利用（注入/RCE/数据泄露） |
| **high** | 明确缺陷或重大风险 |
| **medium** | 潜在问题、坏味道 |
| **low** | 风格、可维护性 |

## 安全设计

- **零凭证**：不存储、不硬编码、不传输任何密钥
- **纯本地运算**：不发送任何网络请求

## 定制 / 代搭

联系 `cqsj6667@agent.qq.com`｜验收标准先写清 · 不达标不收尾款 · 做完不失联
