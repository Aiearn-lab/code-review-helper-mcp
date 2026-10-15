# code-review-helper-mcp · 全自动代码审查交付管线

> 知微工作室 · Zhiwei Studio｜2026-10-15｜v2.0.0｜Node 18+，MIT

把代码审查交付从 30 分钟压到 5 分钟。三个工具：**scan_code**（规则扫描）+ **gen_report**（单文件报告）+ **review_repo**（GitHub 仓库全自动审查）。零第三方依赖。

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

## 三个工具

### `scan_code`（v1）

扫描代码中的安全问题和坏味道。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `code` | `string` | 是 | 要扫描的代码文本 |
| `filename` | `string` | 否 | 文件名（用于语言推断和报告展示） |

### `gen_report`（v1）

把 scan_code 的结果生成 Markdown 审查报告。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `scanResult` | `object` | 是 | scan_code 的完整返回结果 |

### `review_repo`（v2 新增）

全自动代码审查：输入 GitHub 仓库 URL → 拉取代码 → 逐文件扫描 → 生成完整交付报告。

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `repoUrl` | `string` | 是 | GitHub 仓库 URL（支持 `/tree/branch/path` 格式） |
| `maxFiles` | `number` | 否 | 最大扫描文件数，默认 50 |

**工程细节：**
- 通过 GitHub 公开 API 拉取（免认证，60 次/小时限流）
- 自动跳过 `node_modules` / `dist` / `.min.js` / 二进制 / 大文件(>1MB)
- 请求间隔 ≥1s 防封
- 限流(403)明确报错 + 重置时间提示
- 报告按严重级排序（critical → high → medium → low）
- critical/high 发现必须带修复建议代码

**调用示例（对 agent 说）：**

> 帮我审查这个仓库的代码：https://github.com/octocat/Hello-World

## 检测规则

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

## 严重级定义

| 级 | 含义 |
|---|---|
| **critical** | 可被直接利用（注入/RCE/数据泄露） |
| **high** | 明确缺陷或重大风险 |
| **medium** | 潜在问题、坏味道 |
| **low** | 风格、可维护性 |

## 报告结构

1. 概述（文件数 / 行数 / 工具 / 日期）
2. 发现汇总表（# | file:line | 严重级 | 一句话）
3. 详细发现（位置 + 片段 + 说明 + 修复建议）
4. 安全专项
5. 验证记录
6. 修订说明

## 安全设计

- **零凭证**：不存储、不硬编码、不传输任何密钥（不放 GitHub token）
- **纯本地运算**：扫描引擎本地运行，仅 review_repo 调用 GitHub 公开 API

## 定制 / 代搭

联系 `cqsj6667@agent.qq.com`｜验收标准先写清 · 不达标不收尾款 · 做完不失联
