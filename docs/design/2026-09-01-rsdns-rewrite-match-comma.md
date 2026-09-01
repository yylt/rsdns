# rsdns rewrite match 支持逗号分隔的占位符模板

- 日期: 2026-09-01
- 状态: 已实现

## 背景

`match` 目前支持四种形式：空（match-all）、`group:{name}`、逗号分隔的
内联域名集合（如 `a.com,b.com`）、`{N}.{domain}` 占位符模板（如
`{1}.example.com`）。其中**只有**占位符模板不支持逗号分隔——一条规则
只能写一个模板。

对于 `rewrite`（以及 `cname`）这类依赖模板捕获的动作，实际部署中常需要
让多个后缀共享同一套占位符规则。例如按捕获的节点号重写 IP：

```yaml
- match: "{1}.32.0.2.example.com"
  action:
    type: rewrite
    target: "{1}.32.0.2"
```

当需要同时覆盖 `example.com` 和 `example.net` 时，当前只能复制两条规则；
随着后缀增多（地域/运营商/CDN 节点），维护成本线性上升。

## 方案

扩展**占位符模板**形式，允许用逗号分隔多个模板，任一模板命中即应用该
规则。捕获语义与单模板完全一致（`{N}` 从后缀侧捕获 label，写入
`ctx.captures` 供 `rewrite.target` / `cname.target` 替换）。

```yaml
- match: "{1}.32.0.2.example.com,{1}.32.0.2.example.net"
  action:
    type: rewrite
    target: "{1}.32.0.2"
```

### 语法判定

`parse_match_target` 现有判定顺序：

1. 空 / `*` → `MatchAll`
2. `group:` 前缀 → `Group`
3. 含 `{` 或 `}` → 模板
4. 其余 → `InlineDomains`

调整第 3 步：含 `{` / `}` 时**先按逗号切分**，若任一段含 `{` / `}` 则
整体按模板列表解析（每段复用现有 `parse_template`，任一失败 → 配置错误）；
否则（含逗号但无占位符）回落为现有 `InlineDomains` 路径，行为不变。

### 表示

`MatchTarget::Template` 由单个 `TemplatePattern` 改为
`Vec<TemplatePattern>`（列表语义：任一匹配即命中）：

```rust
Template(Vec<TemplatePattern>),
```

- 单模板（现状） = 单元素列表，现有测试语义不变。
- `TemplatePattern` 结构不变（`suffix` + `placeholders`）。
- 匹配时对每个模板执行 `template_match`，任一成功即把捕获写入
  `ctx.captures` 并命中。

### 兼容性

- 所有现有单模板配置（含 `cname` / `forward` / `block` 的模板 match）不受影响。
- 内联域名集合、`group:`、空 match 路径完全不变。
- 不引入新配置字段。

## 实现

- `src/plugins/rules.rs`：
  - `MatchTarget::Template(Vec<TemplatePattern>)`。
  - `parse_match_target`：含 `{`/`}` 时按逗号切分逐段 `parse_template`。
  - `Rule::matches`：对模板列表逐个 `template_match`，首个成功写入捕获并命中。
  - 涉及 `Template` 的模式匹配处同步更新（`matches` 一处）。
- `src/config.rs`：`RuleConfig.r#match` 文档注释补充模板列表语法说明。

## 测试

- `rules`：
  - `match: "{1}.a.com,{1}.b.com"` 解析为双模板列表。
  - 命中任一后缀 → `template_match` 捕获正确、规则命中。
  - 未命中所有后缀 → 不命中。
  - 单模板（现状）解析结果仍为单元素列表，现有断言等价。
  - 非法段（如 `{1}.a.com,{1}.b`）→ 配置错误。
