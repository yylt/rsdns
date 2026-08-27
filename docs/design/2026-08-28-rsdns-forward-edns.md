# rsdns forward rule EDNS(ECS) 支持

- 日期: 2026-08-28
- 状态: 已实现

## 背景

在部分部署场景（服务器位于 NAT 之后、上游需要按客户端地域解析）下，
`forward` 到上游池的 DNS 查询需要携带 EDNS Client Subnet（RFC 7871，
下文简称 ECS）选项，让上游按指定网段做地域解析。

## 配置

`forward` 规则动作新增可选字段 `edns`，格式为 CIDR 字符串，例如
`203.0.113.0/24`。仅支持单条 CIDR。

```yaml
rules:
  - match: "google.com"
    action:
      type: forward
      upstream: overseas
      edns: "203.0.113.0/24"
```

解析失败（非法 CIDR）按规则解析的容错惯例处理：记录 warning、禁用该
规则的 EDNS 通告（该规则退化为普通 forward），不阻止启动。

## 语义

- **固定通告**：`edns` 配置的是通告给上游的固定 CIDR（ECS 的 source
  prefix = CIDR 前缀长度，scope prefix = 0）。不依赖客户端 IP。
- 仅该 forward 规则发出的查询携带 ECS 选项；未配置 `edns` 的规则行为
  完全不变。
- `resolve_cname: true` 时的 CNAME target 二次查询同样携带该选项。
- 仅限 `forward` 动作；`cname` 动作不提供 `edns` 字段。

## 实现

- `src/config.rs`：`RuleActionConfig::Forward` 增加 `Option<String>`
  `edns` 字段（`#[serde(default)]`）。
- `src/plugins/rules.rs`：
  - `RuleAction::Forward` 持有解析后的 `Option<ClientSubnet>`（构建期
    通过 `parse_rule_edns` 解析，非法 CIDR → warning + `None`）。
  - `forward_query` 查询前若配置了 ECS，克隆 `ctx.msg` 并调用
    `crate::upstream::apply_edns` 附加选项；`resolve_cnames` 的 target
    二次查询同样附加。
- `src/upstream/mod.rs`：新增 `pub(crate) fn apply_edns(msg, subnet)` ——
  无 OPT 记录时新建并插入 `EdnsOption::Subnet`，已有 OPT 时仅插入该选项，
  不重复、不覆盖其他字段。`UpstreamClient` / `UpstreamGroup` 本身不感知
  ECS（`forward` 规则层负责注入）。

## 测试

- `config`：`forward` 动作的 `edns` 字段解析（合法 CIDR / 缺省为 `None`）。
- `upstream`：`apply_edns` 附加选项内容正确、保留已有 OPT 选项、不重复插入。
- `rules`：`parse_rule_edns` 合法 CIDR 解析、非法 CIDR 回退为 `None`。
