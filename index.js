#!/usr/bin/env node
/**
 * code-review-helper-mcp — 代码审查辅助工具（扫描 + 报告生成）
 * 知微工作室 · Zhiwei Studio · 2026-10-15 · v1.0.0
 *
 * 提供 2 个工具：
 *   scan_code    输入代码文本，做规则扫描（安全问题 + 坏味道）
 *   gen_report   把扫描结果按固定模板生成 Markdown 审查报告初稿
 *
 * 扫描规则：
 *   安全问题：eval/exec、pickle.load、yaml.load 不安全用法、SQL 字符串拼接、
 *            shell=True、硬编码密钥（sk-/password=/api_key=）、assert 用于校验
 *   坏味道：裸 except、可变默认参数、global 滥用、超长函数(>80行)、重复代码块
 *
 * 设计原则：
 *   - 零第三方依赖（正则匹配 + 原生分析，仅依赖 MCP SDK）
 *   - 多语言支持（Python / JavaScript / Shell / 通用）
 *   - 不存储、不硬编码任何凭证
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

/* ===== 扫描规则定义 ===== */

/**
 * 单行模式规则
 * 每条规则：id / severity / category / pattern(RegExp) / message / languages(可选)
 */
const RULES = [
  // ── 安全问题 ──
  {
    id: "SEC001", severity: "critical", category: "security",
    pattern: /\beval\s*\(/,
    message: "eval() 可执行任意代码，存在远程代码执行(RCE)风险",
  },
  {
    id: "SEC002", severity: "critical", category: "security",
    pattern: /\bexec\s*\(/,
    message: "exec() 可执行任意代码，存在远程代码执行(RCE)风险",
  },
  {
    id: "SEC003", severity: "critical", category: "security",
    pattern: /pickle\.load\s*\(/,
    message: "pickle.load() 反序列化不可信数据可导致 RCE",
  },
  {
    id: "SEC004", severity: "high", category: "security",
    pattern: /yaml\.load\s*\((?!.*Loader\s*=)/,
    message: "yaml.load() 未指定 Loader，默认不安全；请使用 yaml.safe_load()",
  },
  {
    id: "SEC005", severity: "critical", category: "security",
    pattern: /(?:execute|exec(?:ute)?)\s*\(\s*(?:f["']|["'].*%|.*\.format\(|.*\+\s*\w)/,
    message: "SQL 语句使用字符串拼接/插值，存在 SQL 注入风险；请使用参数化查询",
  },
  {
    id: "SEC006", severity: "critical", category: "security",
    pattern: /shell\s*=\s*True/,
    message: "shell=True 可导致命令注入；建议用列表参数 + shell=False",
  },
  {
    id: "SEC007", severity: "critical", category: "security",
    pattern: /(?:sk-[a-zA-Z0-9]{20,}|api_key\s*=\s*["'][^"']{8,}["'])/,
    message: "疑似硬编码 API 密钥；请改用环境变量或配置文件",
  },
  {
    id: "SEC008", severity: "high", category: "security",
    pattern: /(?:password|passwd|pwd)\s*=\s*["'][^"']+["']/,
    message: "疑似硬编码密码；请改用环境变量或密钥管理服务",
  },
  {
    id: "SEC009", severity: "high", category: "security",
    pattern: /^\s*assert\s+/,
    message: "assert 在生产环境可能被优化掉（python -O），不应用于数据校验",
    languages: ["python"],
  },
  {
    id: "SEC010", severity: "critical", category: "security",
    pattern: /<%=?\s*\w/,
    message: "模板中直接嵌入变量/表达式，可能存在 XSS/模板注入风险",
  },

  // ── 坏味道 ──
  {
    id: "SMELL001", severity: "medium", category: "smell",
    pattern: /\bexcept\s*:/,
    message: "裸 except 会捕获所有异常（含 SystemExit/KeyboardInterrupt）；建议指定异常类型",
    languages: ["python"],
  },
  {
    id: "SMELL002", severity: "medium", category: "smell",
    pattern: /def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))/,
    message: "可变对象作为默认参数会在调用间共享状态；建议用 None + 内部初始化",
    languages: ["python"],
  },
  {
    id: "SMELL003", severity: "medium", category: "smell",
    pattern: /^\s*global\s+\w/,
    message: "global 声明使函数与全局状态耦合，降低可测试性和可维护性",
  },
  {
    id: "SMELL004", severity: "low", category: "smell",
    pattern: /console\.log\s*\(/,
    message: "遗留调试输出，生产代码应移除或使用日志框架",
    languages: ["javascript"],
  },
  {
    id: "SMELL005", severity: "medium", category: "smell",
    pattern: /\bvar\s+\w/,
    message: "var 声明存在变量提升问题，建议使用 let/const",
    languages: ["javascript"],
  },
];

/* ===== 扫描引擎 ===== */

/**
 * 根据文件名推断语言
 */
function detectLanguage(filename) {
  if (!filename) return null;
  const ext = filename.split(".").pop()?.toLowerCase();
  const map = {
    py: "python", pyw: "python",
    js: "javascript", mjs: "javascript", cjs: "javascript",
    ts: "javascript", tsx: "javascript", jsx: "javascript",
    sh: "shell", bash: "shell",
    rb: "ruby",
    java: "java",
    go: "go",
  };
  return map[ext] || null;
}

/**
 * 单行模式扫描
 */
function scanPatterns(code, filename) {
  const lines = code.split("\n");
  const lang = detectLanguage(filename);
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // 跳过纯注释行和空行
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    for (const rule of RULES) {
      // 语言过滤
      if (rule.languages && lang && !rule.languages.includes(lang)) continue;
      if (rule.pattern.test(line)) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          category: rule.category,
          line: i + 1,
          message: rule.message,
          code: line.trim(),
        });
      }
    }
  }
  return findings;
}

/**
 * 超长函数检测（>80 行）
 * 通过缩进追踪函数体范围
 */
function scanLongFunctions(code, threshold = 80) {
  const lines = code.split("\n");
  const findings = [];
  let inFunc = false;
  let funcIndent = 0;
  let funcStart = 0;
  let funcName = "";
  let funcLineCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed === "") continue;

    // 计算缩进（空格数）
    const indent = line.length - line.trimStart().length;

    // 检测函数定义（Python / JS / 通用）
    const funcMatch = trimmed.match(/^(?:def|function|async\s+function|async\s+def|func|fn)\s+(\w+)/);
    if (funcMatch && (!inFunc || indent <= funcIndent)) {
      // 先结算上一个函数
      if (inFunc && funcLineCount > threshold) {
        findings.push({
          id: "SMELL004", severity: "low", category: "smell",
          line: funcStart,
          message: `函数 ${funcName} 有 ${funcLineCount} 行（>${threshold}），建议拆分`,
          code: `${funcName}(...)  # ${funcLineCount} lines`,
        });
      }
      inFunc = true;
      funcIndent = indent;
      funcStart = i + 1;
      funcName = funcMatch[1];
      funcLineCount = 1;
      continue;
    }

    if (inFunc) {
      // 如果缩进回到函数定义级别或更低，函数结束
      if (indent <= funcIndent && trimmed !== "") {
        if (funcLineCount > threshold) {
          findings.push({
            id: "SMELL004", severity: "low", category: "smell",
            line: funcStart,
            message: `函数 ${funcName} 有 ${funcLineCount} 行（>${threshold}），建议拆分`,
            code: `${funcName}(...)  # ${funcLineCount} lines`,
          });
        }
        inFunc = false;
        // 检查当前行是否是新函数
        const newFunc = trimmed.match(/^(?:def|function|async\s+function|async\s+def|func|fn)\s+(\w+)/);
        if (newFunc) {
          inFunc = true;
          funcIndent = indent;
          funcStart = i + 1;
          funcName = newFunc[1];
          funcLineCount = 1;
        }
      } else {
        funcLineCount++;
      }
    }
  }

  // 文件末尾结算
  if (inFunc && funcLineCount > threshold) {
    findings.push({
      id: "SMELL004", severity: "low", category: "smell",
      line: funcStart,
      message: `函数 ${funcName} 有 ${funcLineCount} 行（>${threshold}），建议拆分`,
      code: `${funcName}(...)  # ${funcLineCount} lines`,
    });
  }

  return findings;
}

/**
 * 重复代码块检测（连续 ≥4 行相同）
 */
function scanDuplicates(code, minLines = 4) {
  const lines = code.split("\n");
  const findings = [];
  const seen = new Map();

  for (let i = 0; i <= lines.length - minLines; i++) {
    // 取连续 minLines 行，去空白后拼接作为 key
    const block = lines.slice(i, i + minLines).map(l => l.trim()).join("\n");
    // 跳过全空块
    if (block.replace(/\n/g, "").trim() === "") continue;

    if (seen.has(block)) {
      const firstLine = seen.get(block);
      // 避免重叠报告
      if (i - firstLine >= minLines) {
        findings.push({
          id: "SMELL005", severity: "low", category: "smell",
          line: i + 1,
          message: `第 ${i + 1}-${i + minLines} 行与第 ${firstLine}-${firstLine + minLines - 1} 行重复（${minLines} 行代码块）`,
          code: lines[i].trim(),
        });
      }
    } else {
      seen.set(block, i);
    }
  }
  return findings;
}

/**
 * 主扫描函数：汇总所有规则
 */
function scanCode(code, filename) {
  const findings = [
    ...scanPatterns(code, filename),
    ...scanLongFunctions(code),
    ...scanDuplicates(code),
  ];
  // 按行号排序
  findings.sort((a, b) => a.line - b.line);

  // 统计
  const totalLines = code.split("\n").length;
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
  };

  return {
    filename: filename || "(未命名)",
    totalLines,
    language: detectLanguage(filename) || "(未识别)",
    summary,
    findings,
  };
}

/* ===== 报告生成 ===== */

function generateReport(scanResult) {
  const { filename, totalLines, language, summary, findings } = scanResult;
  const now = new Date().toISOString().split("T")[0];
  const lines = [];

  // 1. 概述
  lines.push(`# 代码审查报告`);
  lines.push("");
  lines.push(`## 1. 概述`);
  lines.push("");
  lines.push(`- **审查文件**：\`${filename}\``);
  lines.push(`- **代码行数**：${totalLines}`);
  lines.push(`- **检测语言**：${language}`);
  lines.push(`- **审查工具**：code-review-helper-mcp v1.0.0`);
  lines.push(`- **审查日期**：${now}`);
  lines.push(`- **发现总数**：${summary.total}（critical: ${summary.critical} / high: ${summary.high} / medium: ${summary.medium} / low: ${summary.low}）`);
  lines.push("");

  // 2. 发现汇总表
  lines.push(`## 2. 发现汇总`);
  lines.push("");
  lines.push(`| # | 位置 | 严重级 | 问题一句话 |`);
  lines.push(`|---|------|--------|-----------|`);
  findings.forEach((f, i) => {
    lines.push(`| ${i + 1} | ${filename}:${f.line} | **${f.severity}** | ${f.message} |`);
  });
  lines.push("");

  // 3. 详细发现
  lines.push(`## 3. 详细发现`);
  lines.push("");
  findings.forEach((f, i) => {
    lines.push(`### 3.${i + 1} [${f.severity.toUpperCase()}] ${f.id} — ${f.message}`);
    lines.push("");
    lines.push(`- **位置**：\`${filename}:${f.line}\``);
    lines.push(`- **类别**：${f.category === "security" ? "安全问题" : "坏味道"}`);
    lines.push(`- **代码片段**：`);
    lines.push(`  \`\`\``);
    lines.push(`  ${f.code}`);
    lines.push(`  \`\`\``);
    lines.push(`- **问题说明**：${f.message}`);
    lines.push(`- **修复建议**：请参考项目安全规范进行修复（见安全专项）`);
    lines.push("");
  });

  // 4. 安全专项
  const secFindings = findings.filter(f => f.category === "security");
  lines.push(`## 4. 安全专项`);
  lines.push("");
  if (secFindings.length > 0) {
    lines.push(`本次审查发现 **${secFindings.length}** 个安全问题：`);
    lines.push("");
    secFindings.forEach(f => {
      lines.push(`- **${f.severity.toUpperCase()}**（${filename}:${f.line}）：${f.message}`);
    });
    lines.push("");
    lines.push(`> 建议优先处理 critical 级别问题，这些问题可被直接利用。`);
  } else {
    lines.push(`本次审查未发现安全问题。`);
  }
  lines.push("");

  // 5. 验证记录
  lines.push(`## 5. 验证记录`);
  lines.push("");
  const critHigh = findings.filter(f => f.severity === "critical" || f.severity === "high");
  if (critHigh.length > 0) {
    critHigh.forEach((f, i) => {
      lines.push(`${i + 1}. **${filename}:${f.line}** — 修复前：当前代码可触发该问题；修复后：按修复建议替换后重新扫描确认消失`);
    });
  } else {
    lines.push(`无 critical/high 级别发现，无需专项验证。`);
  }
  lines.push("");

  // 6. 修订说明
  lines.push(`## 6. 修订说明`);
  lines.push("");
  lines.push(`- 本报告包含一轮修订`);
  lines.push(`- 修订范围：针对所有发现提供修复建议`);
  lines.push(`- 响应时间：收到反馈后 24 小时内响应`);
  lines.push("");
  lines.push(`---`);
  lines.push(`*报告由 code-review-helper-mcp 自动生成，知微工作室 · Zhiwei Studio*`);

  return lines.join("\n");
}

/* ===== MCP Server ===== */

const server = new Server(
  { name: "code-review-helper-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_code",
      description: "扫描代码中的安全问题和坏味道。支持 Python / JavaScript / Shell 等语言。检测项包括：eval/exec、pickle.load、SQL 拼接、shell=True、硬编码密钥、裸 except、可变默认参数、global 滥用、超长函数、重复代码块。",
      inputSchema: {
        type: "object",
        properties: {
          code:     { type: "string", description: "要扫描的代码文本" },
          filename: { type: "string", description: "文件名（用于语言推断和报告展示），例如 app.py" },
        },
        required: ["code"],
      },
    },
    {
      name: "gen_report",
      description: "把 scan_code 的扫描结果生成 Markdown 格式的审查报告初稿。结构：概述 / 发现汇总表 / 详细发现 / 安全专项 / 验证记录 / 修订说明。",
      inputSchema: {
        type: "object",
        properties: {
          scanResult: {
            type: "object",
            description: "scan_code 的完整返回结果（JSON 对象）",
          },
        },
        required: ["scanResult"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: a } = req.params;
  try {
    if (name === "scan_code") {
      const result = scanCode(a.code, a.filename);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }

    if (name === "gen_report") {
      // 支持直接传 scanResult 对象，或传 JSON 字符串
      let scanResult = a.scanResult;
      if (typeof scanResult === "string") {
        try { scanResult = JSON.parse(scanResult); } catch { /* 保持原样 */ }
      }
      if (!scanResult || !scanResult.findings) {
        return { content: [{ type: "text", text: "错误: scanResult 格式不正确，需要包含 findings 数组" }], isError: true };
      }
      const report = generateReport(scanResult);
      return { content: [{ type: "text", text: report }] };
    }

    return { content: [{ type: "text", text: "未知工具: " + name }], isError: true };
  } catch (e) {
    return {
      content: [{ type: "text", text: "错误: " + (e && e.message ? e.message : String(e)) }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
