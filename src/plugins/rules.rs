//! `rules` stage — ordered routing rules.
//!
//! Pipeline position: after `cache`.  Rules are evaluated in order; the
//! first match decides:
//!
//! - `block` → NXDomain or poison response, `Respond`;
//! - `cname` → synthesize a CNAME record and resolve the target through the
//!   named upstream, `Respond`;
//! - `forward` → **terminal**: query the named upstream directly via the
//!   assembled [`crate::upstream::Upstreams`] and fill `ctx.response`,
//!   `Respond` (there is no separate upstream pipeline stage); `max_answers`
//!   caps the number of answer records returned (default 5, `0` = no limit);
//!   `resolve_cname: true` resolves the target when the response's first
//!   answer is a CNAME (only the last CNAME of a pure CNAME chain is
//!   resolved; A/AAAA replaces it with owner = queried name, empty drops
//!   it and stops, CNAME keeps the original response); `edns: "cidr"` adds
//!   an EDNS Client Subnet (RFC 7871) option to every query this rule
//!   sends (including `resolve_cname` follow-ups);
//! - `rewrite` → **terminal**: synthesize an A record for the query name
//!   from the `target` (literal dotted-quad IPv4 or `{N}` placeholder
//!   template filled from the match captures, e.g. `{1}.32.0.2`), `Respond`
//!   (no upstream query); non-A/ANY qtypes → NODATA;
//! - no match → NXDOMAIN `Respond` (or keep the stale fallback when the
//!   cache served one).
//!
//! `match` accepts exactly four forms (see the design doc §5): empty
//! (match-all), `group:{name}`, an inline domain set (`a.com,b.com`; a
//! single bare domain is a one-element set), and the `{1}.{domain}`
//! placeholder template — a literal suffix preceded by `{N}` placeholders.
//! Each `{N}` captures the query label directly before the suffix (e.g.
//! `match: "{1}.example.com"` captures `foo` from `foo.example.com`); the
//! capture is stored in `ctx.captures` and can be substituted into the
//! rule action (e.g. `cname.target: "{1}.cdn.example.com"`).

use std::io;
use std::str::FromStr;

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::ClientSubnet;
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use log::warn;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::common::domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder};

use crate::config::{BlockResponse as CfgBlockResponse, Config, RuleActionConfig, RuleConfig};
use crate::metrics::{Counter, MetricsRegistry};
use crate::plugins::util::{
    build_nodata, build_nxdomain, build_poison, build_servfail, make_query_msg, make_response_base, parse_name,
    rewrite_ttl_in_response,
};
use crate::query::{QueryContext, Step};

// ---------------------------------------------------------------------------
// Match target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchTarget {
    MatchAll,
    Group(String),
    InlineDomains(Vec<String>),
    /// `{N}.{domain}` placeholder template: literal suffix with `{N}`
    /// placeholders before it, each capturing one query label.
    Template(TemplatePattern),
}

/// Parsed placeholder template, e.g. `{1}.example.com` →
/// `suffix: "example.com"`, `placeholders: [1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplatePattern {
    /// Literal suffix after the last placeholder (e.g. `example.com`).
    pub suffix: String,
    /// Placeholder numbers in order, each capturing one label before the
    /// suffix (`{1}` captures the label directly before it).
    pub placeholders: Vec<u32>,
}

/// 解析 `match` 字符串为 [`MatchTarget`]。
///
/// 支持四种形式：
/// - 空 / 缺省 / `*` → `MatchAll`
/// - `group:{name}` → `Group`
/// - 逗号分隔的内联域名集合（无大括号）→ `InlineDomains`
/// - `{N}.{domain}` 占位符模板（`{N}` 之后必须有字面域名后缀）→ `Template`
pub fn parse_match_target(s: &str) -> Result<MatchTarget, String> {
    let s = s.trim();
    if s.is_empty() || s == "*" {
        return Ok(MatchTarget::MatchAll);
    }
    // group:{name}
    if let Some(name) = s.strip_prefix("group:") {
        if name.is_empty() || name.contains(',') || name.contains('{') || name.contains('}') {
            return Err(format!("invalid group reference {s:?}: expected group:{{name}}"));
        }
        return Ok(MatchTarget::Group(name.to_string()));
    }
    // {N} 占位符模板
    if s.contains('{') || s.contains('}') {
        return parse_template(s);
    }
    // 逗号分隔的内联域名集合；单域名 = 单元素内联列表
    let domains = parse_inline_domains(s)?;
    Ok(MatchTarget::InlineDomains(domains))
}

/// 解析 `{N}.{domain}` 占位符模板。
///
/// 语法：开头是若干 `{N}`（N ≥ 1）占位符（点分隔），之后必须紧跟 `.`
/// 加字面域名后缀（如 `.foo`、`.foo.bar`）；占位符只允许出现在后缀之前。
/// 占位符之间必须以 `.` 分隔；字面后缀沿用域名校验。
fn parse_template(s: &str) -> Result<MatchTarget, String> {
    let segments: Vec<&str> = s.split('.').collect();
    let mut placeholders = Vec::new();
    let mut idx = 0;
    // 扫描开头连续的 {N} 占位符段。
    while idx < segments.len() {
        let seg = segments[idx].trim();
        let Some(inner) = seg.strip_prefix('{').and_then(|p| p.strip_suffix('}')) else {
            break;
        };
        let n: u32 = inner
            .parse()
            .map_err(|_| format!("invalid match target {s:?}: placeholder {{N}} must be a positive integer"))?;
        if n == 0 {
            return Err(format!("invalid match target {s:?}: placeholder index starts at 1"));
        }
        placeholders.push(n);
        idx += 1;
    }
    if placeholders.is_empty() {
        return Err(format!("invalid match target {s:?}: expected {{N}} before the domain suffix"));
    }
    if idx == segments.len() {
        return Err(format!(
            "invalid match target {s:?}: placeholder must be followed by a domain suffix"
        ));
    }
    // 其余段为字面域名后缀。
    let suffix = segments[idx..].join(".");
    if suffix.contains('{') || suffix.contains('}') {
        return Err(format!(
            "invalid match target {s:?}: placeholder must be followed by a literal domain suffix"
        ));
    }
    let suffix = validate_domain(&suffix).ok_or_else(|| format!("invalid match target {s:?}: bad domain suffix"))?;
    Ok(MatchTarget::Template(TemplatePattern { suffix, placeholders }))
}

/// 校验并规范化一个域名（拒绝尾随点）；标签 `[a-z0-9-_]`，不允许前导/尾随
/// `.`、连续点、空标签。
fn validate_domain(s: &str) -> Option<String> {
    if s.is_empty() || s.starts_with('.') || s.ends_with('.') {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty() || label.starts_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return None;
        }
    }
    Some(s.to_string())
}

/// 解析逗号分隔的内联域名集合（无大括号）。
fn parse_inline_domains(s: &str) -> Result<Vec<String>, String> {
    let mut domains = Vec::new();
    for raw in s.split(',') {
        let d = raw.trim();
        if d.is_empty() {
            continue;
        }
        let d = validate_domain(d).ok_or_else(|| format!("invalid inline domain {d:?} in {s:?}"))?;
        domains.push(d);
    }
    if domains.is_empty() {
        return Err(format!("empty inline domain set: {s:?}"));
    }
    Ok(domains)
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum RuleAction {
    Block {
        response: BlockResponse,
    },
    Cname {
        target: String,
        ttl: u32,
        upstream: String,
        deny_qtypes: Vec<RecordType>,
    },
    Forward {
        upstream: String,
        ttl: Option<u32>,
        max_answers: usize,
        deny_qtypes: Vec<RecordType>,
        resolve_cname: bool,
        /// Fixed EDNS Client Subnet advertised to the upstream (RFC 7871).
        subnet: Option<ClientSubnet>,
    },
    Rewrite {
        target: String,
        ttl: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockResponse {
    NXDomain,
    Poison,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub target: MatchTarget,
    pub qtype: Option<RecordType>,
    pub action: RuleAction,
}

impl Rule {
    fn qtype_matches(&self, qtype: RecordType) -> bool {
        match self.qtype {
            None => true,
            Some(expected) => expected == RecordType::ANY || expected == qtype,
        }
    }

    /// 判断当前查询是否命中；命中占位符模板时把捕获写入 `captures`
    /// （下标 = 占位符序号 - 1）。
    fn matches(&self, ctx: &mut QueryContext) -> bool {
        if !self.qtype_matches(ctx.qtype()) {
            return false;
        }
        let domain = ctx.name();
        match &self.target {
            MatchTarget::MatchAll => true,
            MatchTarget::Group(name) => ctx.group.as_deref() == Some(name.as_str()),
            MatchTarget::InlineDomains(domains) => suffix_match_any(domains, domain),
            MatchTarget::Template(t) => template_match(t, domain).is_some_and(|caps| {
                ctx.captures = caps;
                true
            }),
        }
    }
}

/// 内联域名集合的构建期 trie：以规则序号为 tag，避免逐条扫描。
struct InlineTrie {
    trie: DomainSuffixTrie,
    tag_to_idx: Vec<usize>, // tag "0".. → rule idx
}

fn build_inline_trie(rules: &[Rule]) -> Option<InlineTrie> {
    let mut builder = DomainSuffixTrieBuilder::new();
    let mut tag_to_idx = Vec::new();
    let mut any = false;
    for (idx, rule) in rules.iter().enumerate() {
        if let MatchTarget::InlineDomains(domains) = &rule.target {
            any = true;
            let tag = idx.to_string();
            tag_to_idx.push(idx);
            for d in domains {
                builder.insert(d, &tag);
            }
        }
    }
    if !any {
        return None;
    }
    Some(InlineTrie {
        trie: builder.build().expect("FST build failed"),
        tag_to_idx,
    })
}

fn suffix_match_any(domains: &[String], domain: &str) -> bool {
    domains.iter().any(|d| suffix_match(d, domain))
}

/// 后缀匹配：`domain` 是 `pattern` 或 `pattern` 的子域。
fn suffix_match(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    domain == pattern || domain.ends_with(&format!(".{pattern}"))
}

/// 占位符模板匹配：`domain` 必须以字面 `suffix` 结尾；每个 `{N}` 捕获
/// 从后缀侧数第 N 个 label（`{1}` = 后缀前紧邻的 label）。捕获按占位符
/// 顺序放入返回的 `Vec`（下标 = 占位符序号 - 1）。label 不允许为空/含点。
///
/// 例如 `{1}.example.com`：`foo.example.com` → `["foo"]`；
/// `a.b.example.com` → `["b"]`（`{1}` = 后缀前紧邻 label）。
fn template_match(t: &TemplatePattern, domain: &str) -> Option<Vec<String>> {
    let domain = domain.trim_end_matches('.');
    let suffix = t.suffix.trim_end_matches('.');
    let rest = domain.strip_suffix(suffix)?.strip_suffix('.')?;
    // 纯后缀（rest 为空）不构成模板命中。
    if rest.is_empty() {
        return None;
    }
    let labels: Vec<&str> = rest.split('.').collect();
    let mut caps = Vec::with_capacity(t.placeholders.len());
    for &n in &t.placeholders {
        let idx = (labels.len() as u32).checked_sub(n)? as usize;
        let label = labels.get(idx).copied()?;
        if label.is_empty() || label.contains('.') {
            return None;
        }
        caps.push(label.to_string());
    }
    Some(caps)
}

/// 把 `s` 中的 `{N}` 占位符替换为 `captures` 中对应值
/// （`{1}` → `captures[0]`）。无对应捕获时保留原样。
fn substitute_placeholders(s: &str, captures: &[String]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end_rel) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let inner = &after[..end_rel];
        if let Ok(n) = inner.parse::<u32>() {
            if n >= 1 {
                if let Some(v) = captures.get((n as usize) - 1) {
                    out.push_str(v);
                    rest = &after[end_rel + 1..];
                    continue;
                }
            }
        }
        // 未闭合 / 非占位符 / 无捕获：按字面保留。
        out.push('{');
        out.push_str(inner);
        out.push('}');
        rest = &after[end_rel + 1..];
    }
    out.push_str(rest);
    out
}

/// rewrite 动作：把 `target`（字面点分 IPv4 或含 `{N}` 占位符的模板，如
/// `{1}.32.0.2`）用 `captures` 替换后解析为 IPv4，构造 A 应答。
/// 查询类型仅接受 `A` / `ANY`；其余（如 AAAA、MX）返回 NODATA。替换后不是
/// 合法 IPv4 时返回错误（上层转 SERVFAIL）。
fn build_rewrite_response(
    msg: &Message,
    name: &str,
    target: &str,
    captures: &[String],
    ttl: u32,
) -> io::Result<Message> {
    match msg.queries.first().map(|q| q.query_type()) {
        Some(RecordType::A) | Some(RecordType::ANY) => {}
        _ => return build_nodata(msg),
    }
    let ip: Ipv4Addr = substitute_placeholders(target, captures)
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "target is not a valid IPv4"))?;
    let rr_name = parse_name(name)?;
    let mut response = make_response_base(msg)?;
    response.answers.push(Record::from_rdata(rr_name, ttl, RData::A(A(ip))));
    Ok(response)
}

/// 截断应答中的 answer 记录（`max` 为 0 时不过限）。
fn truncate_answers(msg: &mut Message, max: usize) {
    if max > 0 && msg.answers.len() > max {
        msg.answers.truncate(max);
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

struct RulesMetrics {
    evaluated_total: Counter,
    matched_total: Counter,
}

impl RulesMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            evaluated_total: registry.counter("rsdns_rules_evaluated_total", "Queries evaluated against rules", &[]),
            matched_total: registry.counter("rsdns_rules_matched_total", "Rule matches by action", &["action"]),
        }
    }
}

/// The rules stage.
pub struct Rules {
    rules: Vec<Rule>,
    inline_trie: Option<InlineTrie>,
    /// Assembled named upstream pools (queried by forward/cname).
    upstreams: Arc<crate::upstream::Upstreams>,
    metrics: std::sync::OnceLock<RulesMetrics>,
}

/// Builds the rules stage from the `rules:` config section (or none).
pub fn init(config: &Config, registry: &MetricsRegistry, upstreams: Arc<crate::upstream::Upstreams>) -> Rules {
    let raw = config.plugin_sections.get("rules").cloned().unwrap_or_default();
    let configs: Vec<RuleConfig> = if raw.is_null() {
        Vec::new()
    } else {
        serde_yaml::from_value(raw).unwrap_or_default()
    };
    let mut rules = Vec::with_capacity(configs.len());
    for rc in configs {
        let target = match &rc.r#match {
            Some(s) => parse_match_target(s),
            None => Ok(MatchTarget::MatchAll),
        };
        let target = match target {
            Ok(t) => t,
            Err(e) => {
                warn!("rule parse error: {}", e);
                continue;
            }
        };
        let qtype = rc.qtype.as_ref().map(|qt| parse_qtype(qt));
        let action = match &rc.action {
            RuleActionConfig::Block { response } => RuleAction::Block {
                response: match response {
                    CfgBlockResponse::Nxdomain => BlockResponse::NXDomain,
                    CfgBlockResponse::Poison => BlockResponse::Poison,
                },
            },
            RuleActionConfig::Cname {
                target,
                ttl,
                upstream,
                deny_qtypes,
            } => RuleAction::Cname {
                target: target.clone(),
                ttl: ttl.unwrap_or(600),
                upstream: upstream.clone(),
                deny_qtypes: deny_qtypes.iter().map(|qt| parse_qtype(qt)).collect(),
            },
            RuleActionConfig::Forward {
                upstream,
                ttl,
                max_answers,
                deny_qtypes,
                resolve_cname,
                edns,
            } => RuleAction::Forward {
                upstream: upstream.clone(),
                ttl: *ttl,
                max_answers: max_answers.unwrap_or(5),
                deny_qtypes: deny_qtypes.iter().map(|qt| parse_qtype(qt)).collect(),
                resolve_cname: *resolve_cname,
                subnet: parse_rule_edns(edns.as_deref()),
            },
            RuleActionConfig::Rewrite { target, ttl } => RuleAction::Rewrite {
                target: target.clone(),
                ttl: ttl.unwrap_or(300),
            },
        };
        rules.push(Rule { target, qtype, action });
    }
    let inline_trie = build_inline_trie(&rules);
    let metrics = RulesMetrics::new(registry);
    Rules {
        rules,
        inline_trie,
        upstreams,
        metrics: std::sync::OnceLock::from(metrics),
    }
}

fn parse_qtype(s: &str) -> hickory_proto::rr::RecordType {
    let upper = s.to_ascii_uppercase();
    upper
        .parse::<hickory_proto::rr::RecordType>()
        .or_else(|_| s.parse::<u16>().map(RecordType::from))
        .unwrap_or_else(|_| panic!("invalid query type: {s}"))
}

/// Parses the forward rule's `edns` CIDR into a [`ClientSubnet`]; an
/// invalid CIDR logs a warning and disables ECS for that rule.
fn parse_rule_edns(spec: Option<&str>) -> Option<ClientSubnet> {
    match spec {
        None => None,
        Some(s) => match ClientSubnet::from_str(s.trim()) {
            Ok(cs) => Some(cs),
            Err(e) => {
                warn!("rule forward edns: invalid CIDR {:?}: {}", s, e);
                None
            }
        },
    }
}

impl Rules {
    /// 通过 inline trie 快速判定内联域名是否命中（返回匹配的规则 idx）。
    fn inline_hit(&self, domain: &str) -> Option<usize> {
        let trie = self.inline_trie.as_ref()?;
        let tag = trie.trie.lookup(domain)?;
        tag.parse::<usize>().ok().and_then(|i| trie.tag_to_idx.get(i).copied())
    }

    /// 顺序匹配规则并执行动作；无匹配 → NXDOMAIN。`forward` 是**终端**
    /// 动作：直接通过上游 provider 查询并把结果写入 `ctx.response`
    /// （不再有独立的 upstream 管道阶段）。
    pub async fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        if let Some(m) = self.metrics.get() {
            m.evaluated_total.inc();
        }

        let domain = ctx.name().to_string();

        // 先查 inline trie（无组引用的快速路径）
        if let Some(idx) = self.inline_hit(&domain) {
            let rule = &self.rules[idx];
            if rule.qtype_matches(ctx.qtype()) {
                return self.apply_rule(ctx, rule).await;
            }
        }

        // 其余规则顺序匹配（占位符模板命中时把捕获写入 ctx.captures）
        for rule in &self.rules {
            if rule.matches(ctx) {
                return self.apply_rule(ctx, rule).await;
            }
        }

        // 无匹配 → NXDOMAIN。
        match build_nxdomain(&ctx.msg) {
            Ok(resp) => {
                ctx.response = Some(resp);
                ctx.action = "nxdomain".into();
                if let Some(m) = self.metrics.get() {
                    m.matched_total.with_label_values(&["nxdomain"]).inc();
                }
                Step::Respond
            }
            Err(e) => {
                warn!("nxdomain for {} failed: {}", domain, e);
                ctx.response = Some(build_servfail(&ctx.msg));
                ctx.action = "servfail".into();
                Step::Respond
            }
        }
    }

    async fn apply_rule<'a>(&'a self, ctx: &'a mut QueryContext, rule: &'a Rule) -> Step {
        match &rule.action {
            RuleAction::Block { response } => {
                let resp = match response {
                    BlockResponse::NXDomain => build_nxdomain(&ctx.msg),
                    BlockResponse::Poison => build_poison(&ctx.msg, ctx.name(), ctx.qtype()),
                };
                let action_label = match response {
                    BlockResponse::NXDomain => "block-nxdomain",
                    BlockResponse::Poison => "block-poison",
                };
                match resp {
                    Ok(r) => {
                        ctx.response = Some(r);
                        ctx.action = action_label.into();
                        if let Some(m) = self.metrics.get() {
                            m.matched_total.with_label_values(&[action_label]).inc();
                        }
                        Step::Respond
                    }
                    Err(e) => {
                        warn!("block response for {} failed: {}", ctx.name(), e);
                        ctx.response = Some(build_servfail(&ctx.msg));
                        ctx.action = "block".into();
                        Step::Respond
                    }
                }
            }
            RuleAction::Cname {
                target,
                ttl,
                upstream,
                deny_qtypes,
            } => match self.handle_cname(ctx, target, *ttl, upstream, deny_qtypes).await {
                Ok(resp) => {
                    ctx.response = Some(resp);
                    ctx.action = "cname".into();
                    if let Some(m) = self.metrics.get() {
                        m.matched_total.with_label_values(&["cname"]).inc();
                    }
                    Step::Respond
                }
                Err(e) => {
                    warn!("cname for {} -> {} failed: {}", ctx.name(), target, e);
                    ctx.response = Some(build_servfail(&ctx.msg));
                    ctx.action = "cname".into();
                    Step::Respond
                }
            },
            RuleAction::Forward {
                upstream,
                ttl,
                max_answers,
                deny_qtypes,
                resolve_cname,
                subnet,
            } => {
                if deny_qtypes.contains(&ctx.qtype()) {
                    let action_label = format!("forward-nodata({upstream})");
                    match build_nodata(&ctx.msg) {
                        Ok(resp) => {
                            ctx.response = Some(resp);
                            ctx.action = action_label.clone();
                            if let Some(m) = self.metrics.get() {
                                m.matched_total.with_label_values(&["forward"]).inc();
                            }
                            Step::Respond
                        }
                        Err(e) => {
                            warn!("build_nodata for {} failed: {}", ctx.name(), e);
                            ctx.response = Some(build_servfail(&ctx.msg));
                            ctx.action = action_label;
                            Step::Respond
                        }
                    }
                } else {
                    ctx.action = format!("forward({upstream})");
                    if let Some(m) = self.metrics.get() {
                        m.matched_total.with_label_values(&["forward"]).inc();
                    }
                    match self
                        .forward_query(ctx, upstream, *ttl, *max_answers, *resolve_cname, *subnet)
                        .await
                    {
                        Ok(()) => Step::Respond,
                        Err(e) => {
                            warn!("forward {} for {} failed: {}", upstream, ctx.name(), e);
                            ctx.response = Some(build_servfail(&ctx.msg));
                            ctx.action = format!("forward-error({upstream})");
                            Step::Respond
                        }
                    }
                }
            }
            RuleAction::Rewrite { target, ttl } => {
                let action_label = "rewrite";
                if let Some(m) = self.metrics.get() {
                    m.matched_total.with_label_values(&[action_label]).inc();
                }
                ctx.action = action_label.into();
                match build_rewrite_response(&ctx.msg, ctx.name(), target, &ctx.captures, *ttl) {
                    Ok(resp) => {
                        ctx.response = Some(resp);
                        Step::Respond
                    }
                    Err(e) => {
                        warn!("rewrite for {} failed: {}", ctx.name(), e);
                        ctx.response = Some(build_servfail(&ctx.msg));
                        Step::Respond
                    }
                }
            }
        }
    }

    /// 查询 `upstream` 并写入 `ctx.response`；应用 TTL 覆盖与 answer 数目
    /// 截断（`max_answers`，`0` = 不限）。返回 `Ok` 表示拿到了上游响应。
    /// 当 `resolve_cname` 开启且上游应答首条为 CNAME 时，先按 §`resolve_cnames`
    /// 主动解析 target（在 TTL 覆盖与截断之前）。
    async fn forward_query(
        &self,
        ctx: &mut QueryContext,
        upstream: &str,
        ttl: Option<u32>,
        max_answers: usize,
        resolve_cname: bool,
        subnet: Option<ClientSubnet>,
    ) -> io::Result<()> {
        let mut msg = ctx.msg.clone();
        if let Some(subnet) = subnet {
            crate::upstream::apply_edns(&mut msg, &subnet);
        }
        let resp = self.upstreams.query(upstream, &msg).await?;
        let mut resp = resp;
        if resolve_cname {
            self.resolve_cnames(ctx, upstream, &mut resp, subnet).await;
        }
        if let Some(ttl) = ttl {
            rewrite_ttl_in_response(&mut resp, ttl);
        }
        truncate_answers(&mut resp, max_answers);
        ctx.response = Some(resp);
        Ok(())
    }

    /// `forward.resolve_cname`：当应答**首条**是 CNAME 时，用同一 upstream
    /// 以原 qtype 主动解析其 target，按结果替换/丢弃/原样返回（见
    /// `docs/design/2026-08-27-rsdns-forward-resolve-cname.md`）。
    ///
    /// 若开头连续多条都是 CNAME（纯 CNAME 链），**只处理最后一条**：直接解析
    /// 最后一个 target，跳过多级中间链。解析返回 A/AAAA → 用其替换整条 CNAME
    /// 链（owner 改写为原查询名.
    /// 返回空 / 返回 CNAME / 其他类型 / 解析出错 → 原样保留当前响应并结束（不追链）。
    async fn resolve_cnames(
        &self,
        ctx: &QueryContext,
        upstream: &str,
        resp: &mut Message,
        subnet: Option<ClientSubnet>,
    ) {
        let Some(idx) = last_cname_index(&resp.answers) else {
            return;
        };
        let RData::CNAME(cname) = &resp.answers[idx].data else {
            return;
        };
        let target = cname.0.to_utf8();
        let mut target_msg = match make_query_msg(&target, ctx.qtype()) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("resolve_cname target {} for {} invalid: {}", target, ctx.name(), e);
                return;
            }
        };
        if let Some(subnet) = subnet {
            crate::upstream::apply_edns(&mut target_msg, &subnet);
        }
        let resolved = match self.upstreams.query(upstream, &target_msg).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!(
                    "resolve_cname target {} for {} failed: {}, keep original response",
                    target,
                    ctx.name(),
                    e
                );
                return;
            }
        };

        match classify_resolved(&resolved) {
            Resolved::Address => {
                let query_name = ctx.msg.queries.first().map(|q| q.name()).unwrap();
                let replacement = address_records_with_owner(&resolved, query_name);
                resp.answers = replacement;
            }
            Resolved::Empty | Resolved::Cname | Resolved::Other => {
                // 原样返回上游原始响应，停止处理。
            }
        }
    }

    /// CNAME 规则：返回 CNAME 记录，并通过指定 upstream 代查 target 的真实记录。
    /// `target` 中的 `{N}` 占位符先用 `ctx.captures`（来自 match 捕获）替换。
    async fn handle_cname(
        &self,
        ctx: &QueryContext,
        target: &str,
        ttl: u32,
        upstream: &str,
        deny_qtypes: &[RecordType],
    ) -> io::Result<Message> {
        if deny_qtypes.contains(&ctx.qtype()) {
            return build_nodata(&ctx.msg);
        }
        let target = substitute_placeholders(target, &ctx.captures);
        let query_name = ctx.msg.queries.first().map(|q| q.name().clone()).unwrap_or_default();
        let cname_name = parse_name(&target)?;
        let cname_record = Record::from_rdata(query_name.clone(), ttl, RData::CNAME(CNAME(cname_name)));

        let target_msg = make_query_msg(&target, ctx.qtype())?;

        let mut upstream_resp = match self.upstreams.query(upstream, &target_msg).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!(
                    "cname resolve target {} for {} failed: {}, fallback to CNAME only",
                    target,
                    ctx.name(),
                    e
                );
                let mut resp = make_response_base(&ctx.msg)?;
                resp.answers.push(cname_record);
                return Ok(resp);
            }
        };

        upstream_resp.metadata.id = ctx.msg.id;
        upstream_resp.queries = ctx.msg.queries.clone();
        for answer in &mut upstream_resp.answers {
            answer.name = query_name.clone();
        }
        // 与旧实现一致的“仅主查询入缓存”语义：target key 与主 key 不同，暂不写入。
        Ok(upstream_resp)
    }
}

// ---------------------------------------------------------------------------
// resolve_cname 纯函数辅助
// ---------------------------------------------------------------------------

/// 解析结果按首条 answer 的分类（供 `resolve_cnames` 决策）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    /// 首条是 A / AAAA（替换原 CNAME）。
    Address,
    /// 无 answer（丢弃该 CNAME，继续检查下一条）。
    Empty,
    /// 首条是 CNAME（不丢弃，原样返回，不追链）。
    Cname,
    /// 首条是其他类型（原样返回，不破坏数据）。
    Other,
}

/// 按 `resolved` 的**首条 answer** 分类（`Empty` 表示无 answer）。
fn classify_resolved(resolved: &Message) -> Resolved {
    match resolved.answers.first().map(|r| r.record_type()) {
        None => Resolved::Empty,
        Some(RecordType::A) | Some(RecordType::AAAA) => Resolved::Address,
        Some(RecordType::CNAME) => Resolved::Cname,
        Some(_) => Resolved::Other,
    }
}

/// 定位 `answers` 开头**连续 CNAME 链**的最后一个 CNAME 下标。
///
/// 仅当 `answers` 首条是 CNAME 时返回 `Some`；链被打断（出现非 CNAME 记录）
/// 时，链的末尾就是该 CNAME 段落的最后一个。例如：
/// `[CNAME, CNAME, A, A]` → 1（解析第二个 CNAME 的 target）。
fn last_cname_index(answers: &[Record]) -> Option<usize> {
    if answers.first().is_none_or(|r| r.record_type() != RecordType::CNAME) {
        return None;
    }
    let idx = answers
        .iter()
        .take_while(|r| r.record_type() == RecordType::CNAME)
        .count();
    Some(idx - 1)
}

/// 从解析结果中过滤出 A/AAAA 记录，并把 owner name 改写为 `owner`（原查询名）。
fn address_records_with_owner(resolved: &Message, owner: &Name) -> Vec<Record> {
    resolved
        .answers
        .iter()
        .filter(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
        .map(|r| {
            let mut rec = r.clone();
            rec.name = owner.clone();
            rec
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::AAAA;
    use std::net::Ipv6Addr;

    fn parse_ok(s: &str) -> MatchTarget {
        parse_match_target(s).unwrap()
    }

    #[test]
    fn test_parse_rule_edns() {
        // Valid CIDR → parsed subnet.
        let cs = parse_rule_edns(Some("203.0.113.0/24")).expect("valid CIDR parses");
        assert_eq!(cs.addr(), std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)));
        assert_eq!(cs.source_prefix(), 24);
        // Absent → None.
        assert!(parse_rule_edns(None).is_none());
        // Invalid CIDR → None (warning logged, ECS disabled for the rule).
        assert!(parse_rule_edns(Some("not-a-cidr")).is_none());
    }

    #[test]
    fn test_parse_empty_is_match_all() {
        assert_eq!(parse_ok(""), MatchTarget::MatchAll);
        assert_eq!(parse_ok("   "), MatchTarget::MatchAll);
        assert_eq!(parse_ok("*"), MatchTarget::MatchAll);
    }

    #[test]
    fn test_parse_group() {
        assert_eq!(parse_ok("group:ad"), MatchTarget::Group("ad".into()));
    }

    #[test]
    fn test_parse_inline_domains() {
        assert_eq!(
            parse_ok("foo.com,foo.org"),
            MatchTarget::InlineDomains(vec!["foo.com".into(), "foo.org".into()])
        );
        assert_eq!(parse_ok("example.com"), MatchTarget::InlineDomains(vec!["example.com".into()]));
    }

    #[test]
    fn test_parse_template() {
        let tpl = |s: &str| match parse_ok(s) {
            MatchTarget::Template(t) => t,
            other => panic!("expected template, got {other:?}"),
        };
        assert_eq!(
            tpl("{1}.example.com"),
            TemplatePattern {
                suffix: "example.com".into(),
                placeholders: vec![1],
            }
        );
        assert_eq!(
            tpl("{2}.example.com"),
            TemplatePattern {
                suffix: "example.com".into(),
                placeholders: vec![2],
            }
        );
        assert_eq!(
            tpl("{1}.foo.bar"),
            TemplatePattern {
                suffix: "foo.bar".into(),
                placeholders: vec![1],
            }
        );
        assert_eq!(
            tpl("{1}.{2}.foo.bar"),
            TemplatePattern {
                suffix: "foo.bar".into(),
                placeholders: vec![1, 2],
            }
        );
    }

    #[test]
    fn test_parse_rejects_legacy_syntax() {
        // 旧语法（通配符）被拒绝；单域名是合法内联集。
        for bad in ["*.example.com", "group:{x}", "group:a,b", "a..b", ".x", "x."] {
            assert!(parse_match_target(bad).is_err(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn test_parse_rejects_bad_templates() {
        // 占位符后必须有合法域名后缀；{N} 须为正整数且只出现在最前。
        for bad in [
            "{1}",
            "{1}.",
            "{1}.{2}",
            "{0}.example.com",
            "{abc}.example.com",
            "{1.5}.example.com",
            "example.com.{1}",
            "{1}{2}.example.com",
            "cdn.{1}.example.com",
            "a.{1}.example.com",
            ".{1}.example.com",
            "{1}..example.com",
            "{1}.example..com",
            "{1}.-bad.com",
        ] {
            assert!(parse_match_target(bad).is_err(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn test_template_match_captures() {
        let t = |suffix: &str, phs: &[u32]| TemplatePattern {
            suffix: suffix.into(),
            placeholders: phs.to_vec(),
        };
        // {1} 捕获后缀前紧邻 label
        assert_eq!(
            template_match(&t("example.com", &[1]), "foo.example.com"),
            Some(vec!["foo".into()])
        );
        assert_eq!(
            template_match(&t("example.com", &[1]), "a.b.example.com"),
            Some(vec!["b".into()])
        );
        assert_eq!(template_match(&t("foo.bar", &[1]), "a.foo.bar"), Some(vec!["a".into()]));
        // 多占位符：从后缀侧数
        assert_eq!(
            template_match(&t("example.com", &[1, 2]), "a.b.example.com"),
            Some(vec!["b".into(), "a".into()])
        );
        // {2} 需更深前缀
        assert_eq!(template_match(&t("example.com", &[2]), "foo.example.com"), None);
        assert_eq!(
            template_match(&t("example.com", &[2]), "a.b.example.com"),
            Some(vec!["a".into()])
        );
        // 纯后缀 / 非子域不命中
        assert_eq!(template_match(&t("example.com", &[1]), "example.com"), None);
        assert_eq!(template_match(&t("example.com", &[1]), "notexample.com"), None);
        assert_eq!(template_match(&t("example.com", &[1]), "example.org"), None);
    }

    #[test]
    fn test_substitute_placeholders() {
        let caps = vec!["foo".to_string(), "bar".to_string()];
        assert_eq!(substitute_placeholders("{1}.cdn.example.com", &caps), "foo.cdn.example.com");
        assert_eq!(substitute_placeholders("x.{1}.{2}.com", &caps), "x.foo.bar.com");
        // 缺捕获 / 未知 / 未闭合占位符按字面保留
        assert_eq!(substitute_placeholders("{3}.com", &caps), "{3}.com");
        assert_eq!(substitute_placeholders("{x}.com", &caps), "{x}.com");
        assert_eq!(substitute_placeholders("{1", &caps), "{1");
        assert_eq!(substitute_placeholders("no-placeholder.com", &caps), "no-placeholder.com");
    }

    #[test]
    fn test_suffix_match() {
        assert!(suffix_match("example.com", "example.com"));
        assert!(suffix_match("example.com", "sub.example.com"));
        assert!(suffix_match("example.com", "a.b.example.com"));
        assert!(!suffix_match("example.com", "notexample.com"));
        assert!(!suffix_match("example.com", "example.org"));
    }

    #[test]
    fn test_build_rewrite_response() {
        let msg = make_query_msg("node.example.com", RecordType::A).unwrap();

        // 字面 target：无需捕获
        let resp = build_rewrite_response(&msg, "node.example.com", "10.10.0.0", &[], 300).unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].data, RData::A(A(Ipv4Addr::new(10, 10, 0, 0))));
        assert_eq!(resp.answers[0].name.to_utf8(), "node.example.com");
        assert_eq!(resp.answers[0].ttl, 300);
        assert_eq!(resp.answers[0].record_type(), RecordType::A);

        // 占位符 target：捕获替换为 octet
        let caps = vec!["32".to_string(), "0".to_string(), "2".to_string()];
        let resp = build_rewrite_response(&msg, "node.example.com", "{1}.32.0.2", &caps, 300).unwrap();
        assert_eq!(resp.answers[0].data, RData::A(A(Ipv4Addr::new(32, 32, 0, 2))));

        // 自定义 TTL
        let resp = build_rewrite_response(&msg, "node.example.com", "10.10.0.0", &[], 60).unwrap();
        assert_eq!(resp.answers[0].ttl, 60);

        // 非 A / ANY → NODATA（空应答 NOERROR）
        let aaaa = make_query_msg("node.example.com", RecordType::AAAA).unwrap();
        let resp = build_rewrite_response(&aaaa, "node.example.com", "10.10.0.0", &[], 300).unwrap();
        assert!(resp.answers.is_empty());
        assert_eq!(resp.metadata.response_code, hickory_proto::op::ResponseCode::NoError);

        // 替换后非法 IPv4 → 错误（上层转 SERVFAIL）
        assert!(build_rewrite_response(&msg, "node.example.com", "1.2.3", &[], 300).is_err());
        assert!(build_rewrite_response(&msg, "node.example.com", "1.2.3.999", &[], 300).is_err());
        assert!(build_rewrite_response(&msg, "node.example.com", "{1}.2.3.4", &[], 300).is_err());
        assert!(build_rewrite_response(&msg, "node.example.com", "{1}.2.3.4", &["x".to_string()], 300).is_err());
    }

    #[test]
    fn test_truncate_answers() {
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        for i in 1..=8u8 {
            let rec = Record::from_rdata(
                Name::from_utf8("example.com").unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(10, 0, 0, i))),
            );
            msg.answers.push(rec);
        }
        // 默认语义：超过 5 截到 5
        truncate_answers(&mut msg, 5);
        assert_eq!(msg.answers.len(), 5);
        // 不足上限不动
        truncate_answers(&mut msg, 100);
        assert_eq!(msg.answers.len(), 5);
        // 0 = 不限
        let mut msg2 = make_query_msg("example.com", RecordType::A).unwrap();
        for i in 1..=8u8 {
            msg2.answers.push(Record::from_rdata(
                Name::from_utf8("example.com").unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(10, 0, 0, i))),
            ));
        }
        truncate_answers(&mut msg2, 0);
        assert_eq!(msg2.answers.len(), 8);
    }

    #[test]
    fn test_classify_resolved() {
        // 空应答
        let empty = make_query_msg("example.com", RecordType::A).unwrap();
        assert_eq!(classify_resolved(&empty), Resolved::Empty);

        // A / AAAA
        let mut a = make_query_msg("example.com", RecordType::A).unwrap();
        a.answers.push(Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        assert_eq!(classify_resolved(&a), Resolved::Address);

        let mut aaaa = make_query_msg("example.com", RecordType::AAAA).unwrap();
        aaaa.answers.push(Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));
        assert_eq!(classify_resolved(&aaaa), Resolved::Address);

        // CNAME 首条
        let mut cname = make_query_msg("example.com", RecordType::A).unwrap();
        cname.answers.push(Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_utf8("target.example.com").unwrap())),
        ));
        assert_eq!(classify_resolved(&cname), Resolved::Cname);

        // 其他类型（MX）首条
        let mut mx = make_query_msg("example.com", RecordType::MX).unwrap();
        mx.answers.push(Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_utf8("mail.example.com").unwrap(),
            )),
        ));
        assert_eq!(classify_resolved(&mx), Resolved::Other);
    }

    #[test]
    fn test_last_cname_index() {
        let cname = |name: &str, target: &str| {
            Record::from_rdata(
                Name::from_utf8(name).unwrap(),
                300,
                RData::CNAME(CNAME(Name::from_utf8(target).unwrap())),
            )
        };
        let a = |ip: Ipv4Addr| Record::from_rdata(Name::from_utf8("x.example.com").unwrap(), 300, RData::A(A(ip)));

        // 首条非 CNAME → None
        assert_eq!(last_cname_index(&[]), None);
        assert_eq!(last_cname_index(&[a(Ipv4Addr::new(1, 2, 3, 4))]), None);

        // 单条 CNAME → 0
        let single = vec![cname("a.com", "b.com")];
        assert_eq!(last_cname_index(&single), Some(0));

        // 纯 CNAME 链（多条）→ 最后一条的下标
        let chain = vec![
            cname("a.com", "b.com"),
            cname("b.com", "c.com"),
            cname("c.com", "d.com"),
        ];
        assert_eq!(last_cname_index(&chain), Some(2));

        // CNAME 链后接 A：只处理链段，最后一条 CNAME 下标 = 链长 - 1
        let mixed = vec![
            cname("a.com", "b.com"),
            cname("b.com", "c.com"),
            a(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        assert_eq!(last_cname_index(&mixed), Some(1));
    }

    #[test]
    fn test_address_records_with_owner() {
        let target = Name::from_utf8("target.example.com").unwrap();
        let mut resolved = make_query_msg("target.example.com", RecordType::A).unwrap();
        // A + CNAME + AAAA 混合：只保留 A/AAAA，owner 全部改写为原查询名
        resolved
            .answers
            .push(Record::from_rdata(target.clone(), 300, RData::A(A(Ipv4Addr::new(10, 0, 0, 1)))));
        resolved.answers.push(Record::from_rdata(
            Name::from_utf8("other.example.com").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_utf8("x.example.com").unwrap())),
        ));
        resolved
            .answers
            .push(Record::from_rdata(target.clone(), 300, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))));

        let owner = Name::from_utf8("queried.example.com").unwrap();
        let recs = address_records_with_owner(&resolved, &owner);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].record_type(), RecordType::A);
        assert_eq!(recs[0].name, owner);
        assert_eq!(recs[1].record_type(), RecordType::AAAA);
        assert_eq!(recs[1].name, owner);
    }
}
