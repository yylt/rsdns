//! `groups` stage — domain group membership resolution.
//!
//! Each configured group owns an independent `DomainSuffixTrie`
//! ([`GroupTrie`]).  The stage does **not** short-circuit: it resolves
//! which group the queried name belongs to (first match by config order),
//! sets `ctx.group` and `ctx.skip_cache`, then continues the pipeline.
//!
//! Groups can load domains from inline entries and `file://` paths.  Each
//! `file://` source is watched with the `notify` library; on change the
//! group's trie is rebuilt and atomically swapped.

use log::{info, warn};
use notify::{RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;

use crate::common::domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder};

use crate::config::{Config, GroupConfig};
use crate::metrics::{Counter, Gauge, MetricsRegistry};
use crate::plugins::util::is_change_event;
use crate::query::{QueryContext, Step};

/// A reloadable domain source file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupFile(PathBuf);

/// The currently-active trie for one group.
struct GroupTrie {
    trie: DomainSuffixTrie,
    version: u64,
    entry_count: usize,
}

/// Per-group state, shared with the watcher task via `Arc`.
struct GroupState {
    name: String,
    skip_cache: bool,
    skip_speed: bool,
    inline: Vec<String>,
    files: Vec<GroupFile>,
    /// Active trie (atomically replaced on reload).
    current: RwLock<GroupTrie>,
    /// Fingerprint of the last successfully loaded file content.
    last_files: parking_lot::Mutex<Option<Vec<String>>>,
}

impl GroupState {
    fn build_from(cfg: &GroupConfig) -> Self {
        let mut inline = Vec::new();
        let mut files = Vec::new();
        for item in &cfg.domains {
            if let Some(path) = item.strip_prefix("file://").or_else(|| item.strip_prefix("file:")) {
                files.push(GroupFile(PathBuf::from(path)));
            } else {
                inline.push(item.trim_start_matches("*.").to_string());
            }
        }
        let initial = GroupTrie {
            trie: DomainSuffixTrie::new(),
            version: 0,
            entry_count: 0,
        };
        Self {
            name: cfg.name.clone(),
            skip_cache: cfg.skip_cache,
            skip_speed: cfg.skip_speed,
            inline,
            files,
            current: RwLock::new(initial),
            last_files: parking_lot::Mutex::new(None),
        }
    }
}

/// 解析一行域名数据：整行注释/空行忽略；剥 `*.` 前缀。
fn parse_domain_lines(content: &str, out: &mut Vec<String>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 行内可能带尾随注释/空白，取第一个词。
        let domain = line.split_whitespace().next().unwrap_or(line);
        let domain = domain.trim_start_matches("*.");
        if !domain.is_empty() {
            out.push(domain.to_string());
        }
    }
}

/// 用内联域名 + 文件域名构建一张组 trie。
fn build_group_trie(inline: &[String], remote: &[String], version: u64) -> GroupTrie {
    let mut builder = DomainSuffixTrieBuilder::new();
    let mut count = 0usize;
    for d in inline {
        builder.insert(d, "hit");
        count += 1;
    }
    for d in remote {
        builder.insert(d, "hit");
        count += 1;
    }
    let trie = builder.build().expect("FST build failed");
    GroupTrie {
        trie,
        version,
        entry_count: count,
    }
}

/// 读取所有文件源，返回合并后的域名列表。
fn read_file_domains(files: &[GroupFile]) -> std::io::Result<Vec<String>> {
    let mut all = Vec::new();
    for f in files {
        let content = std::fs::read_to_string(&f.0)?;
        parse_domain_lines(&content, &mut all);
    }
    Ok(all)
}

/// 单次组重载：读取文件源，内容有变化则重建 trie 并原子替换。
fn reload_group(state: &Arc<GroupState>, metrics: &GroupsMetrics) {
    let file_domains = match read_file_domains(&state.files) {
        Ok(d) => d,
        Err(e) => {
            warn!("reload group '{}' failed: {}", state.name, e);
            return;
        }
    };

    // 内容指纹：排序后的域名列表。无变化则跳过重建。
    let mut fingerprint = file_domains.clone();
    fingerprint.sort_unstable();
    {
        let mut last = state.last_files.lock();
        if last.as_ref() == Some(&fingerprint) {
            return;
        }
        *last = Some(fingerprint);
    }

    let version = state.current.read().version + 1;
    let new_trie = build_group_trie(&state.inline, &file_domains, version);
    *state.current.write() = new_trie;
    metrics
        .entries
        .with_label_values(&[&state.name])
        .set(state.current.read().entry_count as u64);
    info!(
        "group '{}' reloaded: {} entries (version {})",
        state.name,
        state.current.read().entry_count,
        version
    );
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

struct GroupsMetrics {
    lookup_total: Counter,
    hit_total: Counter,
    entries: Gauge,
}

impl GroupsMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            lookup_total: registry.counter("rsdns_groups_lookup_total", "Group resolution attempts", &[]),
            hit_total: registry.counter("rsdns_groups_hit_total", "Group hits", &["group"]),
            entries: registry.gauge("rsdns_groups_entries", "Entries per group", &["group"]),
        }
    }
}

/// The groups stage.
pub struct Groups {
    groups: Vec<Arc<GroupState>>,
    metrics: std::sync::OnceLock<Arc<GroupsMetrics>>,
}

/// Builds the groups stage from the top-level `groups[]` array, registering
/// metrics and spawning per-file notify watchers.
pub fn init(config: &Config, registry: &MetricsRegistry) -> Groups {
    let metrics = Arc::new(GroupsMetrics::new(registry));
    let mut states: Vec<Arc<GroupState>> = Vec::new();

    for cfg in config.groups.iter() {
        let state = Arc::new(GroupState::build_from(cfg));
        // 初始加载：同步读入内联 + file 源。
        match read_file_domains(&state.files).map(|d| build_group_trie(&state.inline, &d, 0)) {
            Ok(trie) => {
                *state.current.write() = trie;
                info!(
                    "group '{}': {} entries ({} inline, {} file source(s))",
                    state.name,
                    state.current.read().entry_count,
                    state.inline.len(),
                    state.files.len()
                );
            }
            Err(e) => {
                // 保留空 trie，文件变化时重载任务会再尝试；仅告警。
                warn!("group '{}' initial load failed: {}", state.name, e);
            }
        }
        metrics
            .entries
            .with_label_values(&[&state.name])
            .set(state.current.read().entry_count as u64);

        // 有文件源的组：每个文件 spawn 一个 notify watcher，变化时重载。
        for f in &state.files {
            let path = f.0.clone();
            let cb_state = state.clone();
            let cb_metrics = metrics.clone();
            match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else { return };
                if !is_change_event(&event.kind) {
                    return;
                }
                reload_group(&cb_state, &cb_metrics);
            }) {
                Ok(mut watcher) => {
                    if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                        warn!("group '{}': failed to watch {}: {}", state.name, path.display(), e);
                    } else {
                        // 持有 watcher 直到进程退出，保持文件监控存活。
                        tokio::spawn(async move {
                            std::future::pending::<()>().await;
                            drop(watcher);
                        });
                    }
                }
                Err(e) => {
                    warn!("group '{}': failed to watch {}: {}", state.name, path.display(), e);
                }
            };
        }
        states.push(state);
    }

    Groups {
        groups: states,
        metrics: std::sync::OnceLock::from(metrics),
    }
}

impl Groups {
    /// Resolves the queried name's group (first hit by config order),
    /// sets `ctx.group` / `ctx.skip_cache`, and continues the pipeline.
    pub fn handle(&self, ctx: &mut QueryContext) -> Step {
        if let Some(m) = self.metrics.get() {
            m.lookup_total.inc();
        }
        let name = ctx.name();
        for state in &self.groups {
            if state.current.read().trie.lookup(name).is_some() {
                ctx.group = Some(state.name.clone());
                if state.skip_cache {
                    ctx.skip_cache = true;
                }
                if state.skip_speed {
                    ctx.skip_speed = true;
                }
                if let Some(m) = self.metrics.get() {
                    m.hit_total.with_label_values(&[&state.name]).inc();
                }
                return Step::Continue;
            }
        }
        Step::Continue
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_lines_handles_comments_and_wildcards() {
        let mut out = Vec::new();
        parse_domain_lines(
            "# comment\n\ndoubleclick.net\n*.googlesyndication.com\n  spaced.example.com  \n",
            &mut out,
        );
        assert_eq!(
            out,
            vec![
                "doubleclick.net".to_string(),
                "googlesyndication.com".to_string(),
                "spaced.example.com".to_string()
            ]
        );
    }

    #[test]
    fn test_build_group_trie_lookup() {
        let trie = build_group_trie(&["ad.example".to_string()], &["doubleclick.net".to_string()], 0);
        assert!(trie.trie.lookup("sub.ad.example").is_some());
        assert!(trie.trie.lookup("doubleclick.net").is_some());
        assert!(trie.trie.lookup("example.com").is_none());
        assert_eq!(trie.entry_count, 2);
    }

    #[test]
    fn test_group_state_classifies_sources() {
        let cfg = GroupConfig {
            name: "g".into(),
            domains: vec![
                "file:///tmp/a.txt".into(),
                "file:/tmp/b.txt".into(),
                "inline.example".into(),
            ],
            skip_cache: true,
            skip_speed: true,
        };
        let state = GroupState::build_from(&cfg);
        assert_eq!(state.inline, vec!["inline.example".to_string()]);
        assert_eq!(state.files.len(), 2);
        assert_eq!(state.files[0], GroupFile(PathBuf::from("/tmp/a.txt")));
        assert_eq!(state.files[1], GroupFile(PathBuf::from("/tmp/b.txt")));
        assert!(state.skip_cache);
        assert!(state.skip_speed);
    }
}
