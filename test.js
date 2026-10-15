/**
 * code-review-helper-mcp 自测脚本
 * 知微工作室 · Zhiwei Studio · 2026-10-15
 * 运行：node test.js
 */

/* ===== 复制核心函数（精简版，与 index.js 逻辑一致） ===== */

const RULES = [
  { id: "SEC001", severity: "critical", category: "security", pattern: /\beval\s*\(/, message: "eval() RCE" },
  { id: "SEC002", severity: "critical", category: "security", pattern: /\bexec\s*\(/, message: "exec() RCE" },
  { id: "SEC003", severity: "critical", category: "security", pattern: /pickle\.load\s*\(/, message: "pickle.load RCE" },
  { id: "SEC004", severity: "high", category: "security", pattern: /yaml\.load\s*\((?!.*Loader\s*=)/, message: "yaml.load unsafe" },
  { id: "SEC005", severity: "critical", category: "security", pattern: /(?:execute|exec(?:ute)?)\s*\(\s*(?:f["']|["'].*%|.*\.format\(|.*\+\s*\w)/, message: "SQL injection" },
  { id: "SEC006", severity: "critical", category: "security", pattern: /shell\s*=\s*True/, message: "shell=True" },
  { id: "SEC007", severity: "critical", category: "security", pattern: /(?:sk-[a-zA-Z0-9]{20,}|api_key\s*=\s*["'][^"']{8,}["'])/, message: "hardcoded key" },
  { id: "SEC008", severity: "high", category: "security", pattern: /(?:password|passwd|pwd)\s*=\s*["'][^"']+["']/, message: "hardcoded password" },
  { id: "SEC009", severity: "high", category: "security", pattern: /^\s*assert\s+/, message: "assert for validation", languages: ["python"] },
  { id: "SMELL001", severity: "medium", category: "smell", pattern: /\bexcept\s*:/, message: "bare except", languages: ["python"] },
  { id: "SMELL002", severity: "medium", category: "smell", pattern: /def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))/, message: "mutable default", languages: ["python"] },
  { id: "SMELL003", severity: "medium", category: "smell", pattern: /^\s*global\s+\w/, message: "global abuse" },
  { id: "SMELL004", severity: "low", category: "smell", pattern: /console\.log\s*\(/, message: "debug log", languages: ["javascript"] },
  { id: "SMELL005", severity: "medium", category: "smell", pattern: /\bvar\s+\w/, message: "var usage", languages: ["javascript"] },
];

function detectLanguage(filename) {
  if (!filename) return null;
  const ext = filename.split(".").pop()?.toLowerCase();
  const map = { py: "python", js: "javascript", sh: "shell", ts: "javascript" };
  return map[ext] || null;
}

function scanPatterns(code, filename) {
  const lines = code.split("\n");
  const lang = detectLanguage(filename);
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;
    for (const rule of RULES) {
      if (rule.languages && lang && !rule.languages.includes(lang)) continue;
      if (rule.pattern.test(line)) {
        findings.push({ id: rule.id, severity: rule.severity, category: rule.category, line: i + 1, message: rule.message, code: line.trim() });
      }
    }
  }
  return findings;
}

function scanLongFunctions(code, threshold = 80) {
  const lines = code.split("\n");
  const findings = [];
  let inFunc = false, funcIndent = 0, funcStart = 0, funcName = "", funcLineCount = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed === "") continue;
    const indent = line.length - line.trimStart().length;
    const funcMatch = trimmed.match(/^(?:def|function|async\s+function|async\s+def)\s+(\w+)/);
    if (funcMatch && (!inFunc || indent <= funcIndent)) {
      if (inFunc && funcLineCount > threshold) findings.push({ id: "SMELL004", severity: "low", category: "smell", line: funcStart, message: `函数 ${funcName} 有 ${funcLineCount} 行`, code: funcName });
      inFunc = true; funcIndent = indent; funcStart = i + 1; funcName = funcMatch[1]; funcLineCount = 1;
      continue;
    }
    if (inFunc) {
      if (indent <= funcIndent && trimmed !== "") {
        if (funcLineCount > threshold) findings.push({ id: "SMELL004", severity: "low", category: "smell", line: funcStart, message: `函数 ${funcName} 有 ${funcLineCount} 行`, code: funcName });
        inFunc = false;
      } else { funcLineCount++; }
    }
  }
  if (inFunc && funcLineCount > threshold) findings.push({ id: "SMELL004", severity: "low", category: "smell", line: funcStart, message: `函数 ${funcName} 有 ${funcLineCount} 行`, code: funcName });
  return findings;
}

function scanDuplicates(code, minLines = 4) {
  const lines = code.split("\n");
  const findings = [];
  const seen = new Map();
  for (let i = 0; i <= lines.length - minLines; i++) {
    const block = lines.slice(i, i + minLines).map(l => l.trim()).join("\n");
    if (block.replace(/\n/g, "").trim() === "") continue;
    if (seen.has(block)) {
      const firstLine = seen.get(block);
      if (i - firstLine >= minLines) findings.push({ id: "SMELL005", severity: "low", category: "smell", line: i + 1, message: `重复代码块`, code: lines[i].trim() });
    } else { seen.set(block, i); }
  }
  return findings;
}

function scanCode(code, filename) {
  const findings = [...scanPatterns(code, filename), ...scanLongFunctions(code), ...scanDuplicates(code)];
  findings.sort((a, b) => a.line - b.line);
  const totalLines = code.split("\n").length;
  return {
    filename: filename || "(未命名)", totalLines, language: detectLanguage(filename) || "(未识别)",
    summary: {
      total: findings.length,
      critical: findings.filter(f => f.severity === "critical").length,
      high: findings.filter(f => f.severity === "high").length,
      medium: findings.filter(f => f.severity === "medium").length,
      low: findings.filter(f => f.severity === "low").length,
    },
    findings,
  };
}

function generateReport(r) {
  const lines = [];
  lines.push(`# 代码审查报告`);
  lines.push("");
  lines.push(`## 1. 概述`);
  lines.push(`- **审查文件**：\`${r.filename}\``);
  lines.push(`- **代码行数**：${r.totalLines}`);
  lines.push(`- **发现总数**：${r.summary.total}`);
  lines.push("");
  lines.push(`## 2. 发现汇总`);
  lines.push(`| # | 位置 | 严重级 | 问题一句话 |`);
  lines.push(`|---|------|--------|-----------|`);
  r.findings.forEach((f, i) => { lines.push(`| ${i + 1} | ${r.filename}:${f.line} | **${f.severity}** | ${f.message} |`); });
  lines.push("");
  lines.push(`## 3. 详细发现`);
  r.findings.forEach((f, i) => { lines.push(`### 3.${i + 1} [${f.severity.toUpperCase()}] ${f.id}`); lines.push(`- **位置**：\`${r.filename}:${f.line}\``); });
  lines.push("");
  lines.push(`## 4. 安全专项`);
  const sec = r.findings.filter(f => f.category === "security");
  if (sec.length > 0) { lines.push(`发现 ${sec.length} 个安全问题`); sec.forEach(f => { lines.push(`- **${f.severity}**（${r.filename}:${f.line}）：${f.message}`); }); }
  else { lines.push(`未发现安全问题。`); }
  lines.push("");
  lines.push(`## 5. 验证记录`);
  lines.push(`## 6. 修订说明`);
  return lines.join("\n");
}

/* ===== 测试框架 ===== */

let passed = 0, failed = 0;
function assert(cond, msg) { if (cond) { console.log(`  ✓ ${msg}`); passed++; } else { console.error(`  ✗ ${msg}`); failed++; } }
function hasFinding(result, id) { return result.findings.some(f => f.id === id); }

/* ===== 测试用例 ===== */

// [1] eval 检测
console.log("\n[1] SEC001 eval 检测");
{
  const r = scanCode('result = eval(user_input)', "test.py");
  assert(hasFinding(r, "SEC001"), "eval() 被检出");
  assert(r.findings.find(f => f.id === "SEC001").severity === "critical", "eval 为 critical");
}

// [2] exec 检测
console.log("\n[2] SEC002 exec 检测");
{
  const r = scanCode('exec(code_string)', "test.py");
  assert(hasFinding(r, "SEC002"), "exec() 被检出");
}

// [3] pickle.load 检测
console.log("\n[3] SEC003 pickle.load 检测");
{
  const r = scanCode('data = pickle.load(open("f.pkl", "rb"))', "test.py");
  assert(hasFinding(r, "SEC003"), "pickle.load() 被检出");
}

// [4] yaml.load 不安全用法
console.log("\n[4] SEC004 yaml.load 检测");
{
  const r1 = scanCode('data = yaml.load(text)', "test.py");
  assert(hasFinding(r1, "SEC004"), "yaml.load() 无 Loader 被检出");
  const r2 = scanCode('data = yaml.load(text, Loader=yaml.SafeLoader)', "test.py");
  assert(!hasFinding(r2, "SEC004"), "yaml.load() 有 Loader 不触发");
}

// [5] SQL 拼接检测
console.log("\n[5] SEC005 SQL 拼接检测");
{
  const r = scanCode('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")', "test.py");
  assert(hasFinding(r, "SEC005"), "SQL f-string 拼接被检出");
}

// [6] shell=True 检测
console.log("\n[6] SEC006 shell=True 检测");
{
  const r = scanCode('subprocess.run(cmd, shell=True)', "test.py");
  assert(hasFinding(r, "SEC006"), "shell=True 被检出");
}

// [7] 硬编码密钥检测
console.log("\n[7] SEC007 硬编码密钥检测");
{
  const r = scanCode('api_key = "sk-abcdefghijklmnopqrstuvwxyz"', "test.py");
  assert(hasFinding(r, "SEC007"), "硬编码 API key 被检出");
}

// [8] 硬编码密码检测
console.log("\n[8] SEC008 硬编码密码检测");
{
  const r = scanCode('password = "super_secret_123"', "test.py");
  assert(hasFinding(r, "SEC008"), "硬编码密码被检出");
}

// [9] assert 用于校验
console.log("\n[9] SEC009 assert 检测");
{
  const r = scanCode('assert user.is_admin, "需要管理员权限"', "test.py");
  assert(hasFinding(r, "SEC009"), "assert 校验被检出");
}

// [10] 裸 except 检测
console.log("\n[10] SMELL001 裸 except 检测");
{
  const r = scanCode('try:\n    do_something()\nexcept:\n    pass', "test.py");
  assert(hasFinding(r, "SMELL001"), "裸 except 被检出");
}

// [11] 可变默认参数检测
console.log("\n[11] SMELL002 可变默认参数检测");
{
  const r = scanCode('def process(items=[]):\n    pass', "test.py");
  assert(hasFinding(r, "SMELL002"), "可变默认参数被检出");
}

// [12] global 滥用检测
console.log("\n[12] SMELL003 global 检测");
{
  const r = scanCode('def update():\n    global counter\n    counter += 1', "test.py");
  assert(hasFinding(r, "SMELL003"), "global 被检出");
}

// [13] JS: console.log 检测
console.log("\n[13] JS console.log 检测");
{
  const r = scanCode('function test() {\n  console.log("debug");\n}', "app.js");
  assert(hasFinding(r, "SMELL004"), "console.log 被检出");
}

// [14] JS: var 检测
console.log("\n[14] JS var 检测");
{
  const r = scanCode('var x = 10;', "app.js");
  assert(hasFinding(r, "SMELL005"), "var 被检出");
}

// [15] 超长函数检测
console.log("\n[15] 超长函数检测");
{
  // 生成一个 90 行的 Python 函数
  const funcLines = ["def long_function():"];
  for (let i = 0; i < 90; i++) funcLines.push(`    x${i} = ${i}`);
  const r = scanCode(funcLines.join("\n"), "test.py");
  assert(r.findings.some(f => f.message.includes("long_function") && f.message.includes("行")), "超长函数被检出");
}

// [16] 重复代码块检测
console.log("\n[16] 重复代码块检测");
{
  const block = "    a = 1\n    b = 2\n    c = 3\n    d = a + b + c";
  const code = `def first():\n${block}\n\ndef second():\n${block}`;
  const r = scanCode(code, "test.py");
  assert(r.findings.some(f => f.message.includes("重复")), "重复代码块被检出");
}

// [17] 干净代码无误报
console.log("\n[17] 干净代码无安全问题");
{
  const r = scanCode('import os\n\ndef main():\n    path = os.getenv("DATA_PATH")\n    print(path)', "clean.py");
  assert(r.summary.critical === 0, "干净代码无 critical");
  assert(r.summary.high === 0, "干净代码无 high");
}

// [18] gen_report 结构验证
console.log("\n[18] gen_report 报告结构");
{
  const scanResult = scanCode('eval(input())\npassword = "test123"', "vuln.py");
  const report = generateReport(scanResult);
  assert(report.includes("# 代码审查报告"), "报告含标题");
  assert(report.includes("## 1. 概述"), "报告含概述");
  assert(report.includes("## 2. 发现汇总"), "报告含汇总表");
  assert(report.includes("## 3. 详细发现"), "报告含详细发现");
  assert(report.includes("## 4. 安全专项"), "报告含安全专项");
  assert(report.includes("## 5. 验证记录"), "报告含验证记录");
  assert(report.includes("## 6. 修订说明"), "报告含修订说明");
  assert(report.includes("vuln.py:"), "报告含 file:line 格式");
}

// [19] 中文代码扫描
console.log("\n[19] 中文代码扫描");
{
  const r = scanCode('# 这是注释\ndef 处理数据():\n    password = "中文密码123"\n    eval(用户输入)', "中文.py");
  assert(hasFinding(r, "SEC001"), "中文代码中的 eval 被检出");
  assert(hasFinding(r, "SEC008"), "中文代码中的密码被检出");
}

// [20] 注释行跳过
console.log("\n[20] 注释行不触发");
{
  const r = scanCode('# eval(user_input)\n# password = "test"', "test.py");
  assert(r.summary.total === 0, "注释行不触发任何规则");
}

/* ===== v2 新增：review_repo 相关测试 ===== */

// 复制 v2 核心函数（纯函数级测试，不走网络）
const CODE_EXTENSIONS = new Set([".py", ".js", ".mjs", ".ts", ".sh", ".rb", ".java", ".go"]);
const SKIP_PATTERNS = [/node_modules\//, /\/vendor\//, /\.min\.(js|css)$/, /bundle\./, /\/dist\//, /\.lock$/];

function parseGitHubUrl(url) {
  const clean = url.replace(/\/+$/, "");
  const match = clean.match(/github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+)(?:\/(.+))?)?/);
  if (!match) throw new Error(`无法解析 GitHub URL: ${url}`);
  return { owner: match[1], repo: match[2], ref: match[3] || "HEAD", path: match[4] || "" };
}

function shouldScanFile(path) {
  if (SKIP_PATTERNS.some(p => p.test(path))) return false;
  const ext = "." + path.split(".").pop()?.toLowerCase();
  return CODE_EXTENSIONS.has(ext);
}

function generateRepoReport(repoInfo, fileResults) {
  const allFindings = [];
  for (const fr of fileResults) { for (const f of fr.findings) { allFindings.push({ ...f, file: fr.path }); } }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allFindings.sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
  const totalFiles = fileResults.length;
  const totalLines = fileResults.reduce((s, fr) => s + fr.totalLines, 0);
  const summary = {
    total: allFindings.length,
    critical: allFindings.filter(f => f.severity === "critical").length,
    high: allFindings.filter(f => f.severity === "high").length,
    medium: allFindings.filter(f => f.severity === "medium").length,
    low: allFindings.filter(f => f.severity === "low").length,
  };
  const lines = [];
  lines.push(`# 代码审查报告`);
  lines.push(`## 1. 概述`);
  lines.push(`- **审查仓库**：${repoInfo.owner}/${repoInfo.repo}`);
  lines.push(`- **扫描文件数**：${totalFiles}`);
  lines.push(`- **代码总行数**：${totalLines}`);
  lines.push(`- **发现总数**：${summary.total}`);
  lines.push(`## 2. 发现汇总`);
  lines.push(`| # | 位置 | 严重级 | 问题一句话 |`);
  allFindings.forEach((f, i) => { lines.push(`| ${i+1} | ${f.file}:${f.line} | **${f.severity}** | ${f.message} |`); });
  lines.push(`## 3. 详细发现`);
  allFindings.forEach(f => {
    if (f.severity === "critical" || f.severity === "high") lines.push(`- **修复建议**：替换为安全写法`);
  });
  lines.push(`## 4. 安全专项`);
  lines.push(`## 5. 验证记录`);
  lines.push(`## 6. 修订说明`);
  return { totalFiles, totalLines, summary, findings: allFindings, report: lines.join("\n") };
}

// [21] parseGitHubUrl 基本解析
console.log("\n[21] parseGitHubUrl 基本解析");
{
  const r = parseGitHubUrl("https://github.com/octocat/Hello-World");
  assert(r.owner === "octocat", `owner = octocat（实际 ${r.owner}）`);
  assert(r.repo === "Hello-World", `repo = Hello-World（实际 ${r.repo}）`);
  assert(r.ref === "HEAD", `默认 ref = HEAD（实际 ${r.ref}）`);
  assert(r.path === "", `默认 path 为空`);
}

// [22] parseGitHubUrl 带分支和路径
console.log("\n[22] parseGitHubUrl 带分支和路径");
{
  const r = parseGitHubUrl("https://github.com/owner/repo/tree/main/src/lib");
  assert(r.ref === "main", `ref = main（实际 ${r.ref}）`);
  assert(r.path === "src/lib", `path = src/lib（实际 ${r.path}）`);
}

// [23] parseGitHubUrl 无效 URL 报错
console.log("\n[23] parseGitHubUrl 无效 URL");
{
  let threw = false;
  try { parseGitHubUrl("https://gitlab.com/foo/bar"); } catch { threw = true; }
  assert(threw, "非 GitHub URL 抛出异常");
}

// [24] shouldScanFile 过滤
console.log("\n[24] shouldScanFile 文件过滤");
{
  assert(shouldScanFile("src/app.py"), ".py 文件通过");
  assert(shouldScanFile("lib/index.js"), ".js 文件通过");
  assert(!shouldScanFile("image.png"), ".png 不通过");
  assert(!shouldScanFile("node_modules/pkg/index.js"), "node_modules 跳过");
  assert(!shouldScanFile("dist/bundle.js"), "dist 跳过");
  assert(!shouldScanFile("app.min.js"), ".min.js 跳过");
  assert(!shouldScanFile("package-lock.json"), ".lock 跳过");
}

// [25] generateRepoReport 多文件汇总
console.log("\n[25] generateRepoReport 多文件汇总");
{
  const repoInfo = { owner: "test", repo: "demo", ref: "main", path: "" };
  const fileResults = [
    { path: "app.py", totalLines: 50, summary: { total: 2, critical: 1, high: 0, medium: 1, low: 0 },
      findings: [
        { id: "SEC001", severity: "critical", category: "security", line: 10, message: "eval() RCE", code: "eval(x)" },
        { id: "SMELL001", severity: "medium", category: "smell", line: 20, message: "bare except", code: "except:" },
      ] },
    { path: "utils.js", totalLines: 30, summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0 },
      findings: [
        { id: "SEC008", severity: "high", category: "security", line: 5, message: "hardcoded password", code: 'password = "x"' },
      ] },
  ];
  const result = generateRepoReport(repoInfo, fileResults);
  assert(result.totalFiles === 2, `汇总 2 个文件（实际 ${result.totalFiles}）`);
  assert(result.totalLines === 80, `汇总 80 行（实际 ${result.totalLines}）`);
  assert(result.summary.total === 3, `汇总 3 个发现（实际 ${result.summary.total}）`);
  assert(result.summary.critical === 1, "1 个 critical");
  assert(result.summary.high === 1, "1 个 high");
}

// [26] 报告按严重级排序
console.log("\n[26] 报告按严重级排序");
{
  const repoInfo = { owner: "o", repo: "r", ref: "main", path: "" };
  const fileResults = [{
    path: "x.py", totalLines: 10,
    summary: { total: 3, critical: 1, high: 1, medium: 1, low: 0 },
    findings: [
      { id: "SMELL001", severity: "medium", category: "smell", line: 1, message: "m", code: "x" },
      { id: "SEC001", severity: "critical", category: "security", line: 2, message: "c", code: "x" },
      { id: "SEC008", severity: "high", category: "security", line: 3, message: "h", code: "x" },
    ],
  }];
  const result = generateRepoReport(repoInfo, fileResults);
  assert(result.findings[0].severity === "critical", "第一个是 critical");
  assert(result.findings[1].severity === "high", "第二个是 high");
  assert(result.findings[2].severity === "medium", "第三个是 medium");
}

// [27] 报告结构完整性
console.log("\n[27] 多文件报告结构完整");
{
  const repoInfo = { owner: "octocat", repo: "demo", ref: "main", path: "" };
  const fileResults = [{
    path: "main.py", totalLines: 20,
    summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0 },
    findings: [{ id: "SEC001", severity: "critical", category: "security", line: 5, message: "eval", code: "eval(x)" }],
  }];
  const result = generateRepoReport(repoInfo, fileResults);
  assert(result.report.includes("# 代码审查报告"), "报告含标题");
  assert(result.report.includes("## 1. 概述"), "报告含概述");
  assert(result.report.includes("## 2. 发现汇总"), "报告含汇总表");
  assert(result.report.includes("main.py:5"), "报告含 file:line 格式");
  assert(result.report.includes("## 4. 安全专项"), "报告含安全专项");
  assert(result.report.includes("修复建议"), "critical 发现带修复建议");
}

// 汇总
console.log(`\n========== 结果 ==========`);
console.log(`通过: ${passed}  失败: ${failed}`);
if (failed > 0) { console.error("有测试失败！"); process.exit(1); }
else { console.log("全部通过 ✓"); }
