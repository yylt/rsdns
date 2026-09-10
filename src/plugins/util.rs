//! Shared helpers for the rsdns plugins.
//!
//! Pure functions moved out of `server.rs` so that the chain plugins
//! (hosts / cache / rules / upstream) can reuse response construction,
//! caching, and upstream queries without pulling in the server type.

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, MX, TXT};
use hickory_proto::rr::RData;
use hickory_proto::rr::{Name, Record, RecordType};
use log::warn;
use notify::event::{AccessKind, AccessMode, ModifyKind};
use notify::{EventKind, RecursiveMode, Watcher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::plugins::cache::{CacheEntry, CacheKey, CacheRecord, DnsCache};

/// Constructs a DNS query `Message` for `name`/`qtype` (used for upstream
/// resolution of cname targets and background refresh).
///
/// Parses `name` with `parse_name` (strict IDNA first, `from_ascii` fallback),
/// so targets that render non-safe characters (e.g. an underscore in the middle
/// of a label) still produce a valid query instead of failing.
pub(crate) fn make_query_msg(name: &str, qtype: RecordType) -> io::Result<Message> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(parse_name(name)?);
    q.set_query_type(qtype);
    q.set_query_class(hickory_proto::rr::DNSClass::IN);
    msg.queries.push(q);
    msg.metadata.recursion_desired = true;
    Ok(msg)
}

/// Parses a domain string into a hickory `Name`.
///
/// Tries strict IDNA (`from_utf8`) first, then falls back to `from_ascii` which
/// accepts labels that `from_utf8` rejects (e.g. an underscore in the middle of
/// a label, like `path3_new.example.com`). The fallback mirrors
/// `Name::from_str_relaxed` semantics without its IDNA second pass; wire names
/// rendered via `Display`/`to_utf8` (which escape non-safe characters) always
/// re-parse cleanly, so the fallback only accepts names that were already safe
/// on the wire.
pub(crate) fn parse_name(name: &str) -> io::Result<Name> {
    Name::from_utf8(name)
        .or_else(|_| Name::from_ascii(name))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Basic response skeleton mirroring the query's id and question.
///
/// Flags: copies the request's opcode and the RD/CD bits into the response
/// (per RFC 6895 only RD and CD are copied from query to response; RA/AA/AD
/// are set by the server), so request flags are never cleared.
pub(crate) fn make_response_base(msg: &Message) -> io::Result<Message> {
    let mut response = Message::new(msg.id, MessageType::Response, OpCode::Query);
    response.metadata = Metadata::response_from_request(&msg.metadata);
    response.metadata.recursion_available = true;
    if let Some(q) = msg.queries.first() {
        response.queries.push(q.clone());
    }
    Ok(response)
}

/// Rewrites every answer TTL to `ttl`.
pub(crate) fn rewrite_ttl_in_response(msg: &mut Message, ttl: u32) {
    for answer in &mut msg.answers {
        answer.ttl = ttl;
    }
}

/// Extracts cacheable records (A / AAAA / CNAME / MX / TXT / HTTPS).
pub(crate) fn extract_cache_records(msg: &Message) -> Option<Vec<CacheRecord>> {
    let mut records = Vec::new();
    for answer in &msg.answers {
        match &answer.data {
            RData::A(ip) => records.push(CacheRecord::A(ip.0)),
            RData::AAAA(ip) => records.push(CacheRecord::Aaaa(ip.0)),
            RData::CNAME(cname) => records.push(CacheRecord::Cname(cname.0.to_ascii())),
            RData::MX(mx) => records.push(CacheRecord::Mx {
                preference: mx.preference,
                exchange: mx.exchange.to_ascii(),
            }),
            RData::TXT(txt) => {
                let strings: Vec<String> = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect();
                records.push(CacheRecord::Txt(strings))
            }
            RData::HTTPS(https) => records.push(CacheRecord::Https(https.0.clone())),
            _ => {}
        }
    }
    if records.is_empty() {
        None
    } else {
        Some(records)
    }
}

/// Minimum TTL across answers; default 300 for empty responses.
pub(crate) fn extract_min_ttl(msg: &Message) -> u32 {
    msg.answers.iter().map(|r| r.ttl).min().unwrap_or(300)
}

/// Writes an upstream response into the cache (positive + NXDOMAIN negative).
pub(crate) async fn cache_upstream_response(
    cache: &DnsCache,
    cache_key: &CacheKey,
    response: &Message,
    rewrite_ttl: Option<u32>,
) {
    if let Some(records) = extract_cache_records(response) {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), records, final_ttl).await;
        return;
    }

    let rcode = response.metadata.response_code;
    let negative_record = match rcode {
        ResponseCode::NXDomain => Some(CacheRecord::NxDomain),
        ResponseCode::NoError => Some(CacheRecord::NoData),
        _ => None,
    };

    if let Some(record) = negative_record {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), vec![record], final_ttl).await;
    }
}

/// Builds a response from a cache entry, decrementing TTLs.
pub(crate) fn build_response_from_cache(msg: &Message, entry: &CacheEntry, keep_ttl: bool) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    let query = msg
        .queries
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;
    let reply_ttl = entry.remaining_ttl(keep_ttl);
    let records = &entry.records;
    for record in records.iter() {
        let r = match record {
            CacheRecord::A(ip) => Record::from_rdata(query.name().clone(), reply_ttl, RData::A(A(*ip))),
            CacheRecord::Aaaa(ip) => Record::from_rdata(query.name().clone(), reply_ttl, RData::AAAA(AAAA(*ip))),
            CacheRecord::Cname(target) => {
                let cname_name = parse_name(target)?;
                Record::from_rdata(query.name().clone(), reply_ttl, RData::CNAME(CNAME(cname_name)))
            }
            CacheRecord::Mx { preference, exchange } => {
                let exchange_name = parse_name(exchange)?;
                Record::from_rdata(query.name().clone(), reply_ttl, RData::MX(MX::new(*preference, exchange_name)))
            }
            CacheRecord::Txt(txt_data) => {
                Record::from_rdata(query.name().clone(), reply_ttl, RData::TXT(TXT::new(txt_data.clone())))
            }
            CacheRecord::Https(svcb) => {
                Record::from_rdata(query.name().clone(), reply_ttl, RData::HTTPS(HTTPS(svcb.clone())))
            }
            CacheRecord::NxDomain | CacheRecord::NoData => continue,
        };
        response.answers.push(r);
    }

    if let Some(CacheRecord::NxDomain) = records.first() {
        response.metadata.response_code = ResponseCode::NXDomain;
    }
    if let Some(CacheRecord::NoData) = records.first() {
        response.metadata.response_code = ResponseCode::NoError;
    }

    Ok(response)
}

/// Builds a hosts-style response from a static IP list.
pub(crate) fn build_hosts_response(
    msg: &Message,
    name: &str,
    qtype: RecordType,
    ips: &[IpAddr],
) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    let rr_name = parse_name(name)?;

    for ip in ips {
        let record = match (ip, qtype) {
            (IpAddr::V4(v4), RecordType::A) | (IpAddr::V4(v4), RecordType::ANY) => {
                Record::from_rdata(rr_name.clone(), 300, RData::A(A(*v4)))
            }
            (IpAddr::V6(v6), RecordType::AAAA) | (IpAddr::V6(v6), RecordType::ANY) => {
                Record::from_rdata(rr_name.clone(), 300, RData::AAAA(AAAA(*v6)))
            }
            _ => continue,
        };
        response.answers.push(record);
    }

    Ok(response)
}

/// NXDOMAIN response.
pub(crate) fn build_nxdomain(msg: &Message) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    response.metadata.response_code = ResponseCode::NXDomain;
    Ok(response)
}

/// Poison response (A=0.0.0.0, AAAA=::).
pub(crate) fn build_poison(msg: &Message, name: &str, qtype: RecordType) -> io::Result<Message> {
    let mut response = make_response_base(msg)?;
    let rr_name = parse_name(name)?;

    match qtype {
        RecordType::A | RecordType::ANY => {
            let record = Record::from_rdata(rr_name.clone(), 300, RData::A(A(Ipv4Addr::new(0, 0, 0, 0))));
            response.answers.push(record);
            response.metadata.response_code = ResponseCode::NoError;
        }
        _ => {
            response.metadata.response_code = ResponseCode::NoError;
        }
    }
    match qtype {
        RecordType::AAAA | RecordType::ANY => {
            let record = Record::from_rdata(rr_name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
            response.answers.push(record);
        }
        _ => {}
    }

    Ok(response)
}

/// SERVFAIL response (mirrors `make_response_base`, then overwrites rcode).
pub(crate) fn build_servfail(msg: &Message) -> Message {
    let mut response = make_response_base(msg).expect("make_response_base cannot fail");
    response.metadata.response_code = ResponseCode::ServFail;
    response
}

/// NoData response (empty answer, NOERROR).
pub(crate) fn build_nodata(msg: &Message) -> io::Result<Message> {
    make_response_base(msg)
}

/// Watch events that mean "file content finished changing" — the signal to
/// reload.  Only the *completion* of a write counts:
///
/// - `Access(Close(Write))`: an in-place writer (e.g. `curl -o`, shell `>`)
///   truncated + wrote the file in chunks, then closed it — the content is
///   complete only at close.  Reacting to the intermediate `Modify(Data(_))`
///   events would reload partial content multiple times per update.
/// - `Modify(Name(_))`: an atomic rename (`mv tmp → target`) replaced the
///   file — the new content is complete when the rename lands.
///
/// `Create`/`Remove` are also accepted so a brand-new file is picked up.
/// Everything else (`Modify(Data(_))` per chunk, metadata, opens, reads,
/// close-without-write) is ignored.
pub(crate) fn is_change_event(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Access(AccessKind::Close(AccessMode::Write))
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Create(_)
            | EventKind::Remove(_)
            | EventKind::Any
            | EventKind::Other
    )
}

/// Watches `path` and calls `on_change` whenever its content is replaced.
///
/// The watch is installed on the **parent directory**, not on the file itself.
/// Most writers (editors, `sed -i`, `mv tmp target`) replace the file via
/// rename, which unlinks the inode a direct file watch is attached to: that
/// watch is torn down by the kernel after the *first* such edit, so every
/// later change goes unnoticed.  A directory watch survives replacement, and
/// events for sibling files are filtered out by comparing against `path`.
///
/// The watcher is kept alive until process exit.
pub(crate) fn watch_file(path: &Path, on_change: impl Fn() + Send + 'static) {
    // notify 回报的事件路径基于 watch 时传入的目录，可能是绝对路径；
    // 这里统一成绝对路径再比较，避免相对配置路径漏匹配。
    let target = match std::path::absolute(path) {
        Ok(p) => p,
        Err(e) => {
            warn!("cannot watch {}: {}", path.display(), e);
            return;
        }
    };
    let Some(parent) = target.parent() else {
        warn!("cannot watch {}: no parent directory", target.display());
        return;
    };

    let mut watcher = match notify::recommended_watcher({
        let target = target.clone();
        move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if !is_change_event(&event.kind) {
                return;
            }
            if event.paths.iter().any(|p| p == &target) {
                on_change();
            }
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            warn!("cannot watch {}: {}", target.display(), e);
            return;
        }
    };

    if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
        warn!("cannot watch {}: {}", target.display(), e);
        return;
    }

    // 持有 watcher 直到进程退出，保持文件监控存活。
    tokio::spawn(async move {
        std::future::pending::<()>().await;
        drop(watcher);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::cache::{CacheResult, DnsCache};
    use notify::event::{
        AccessKind, AccessMode, CreateKind, DataChange, MetadataKind, ModifyKind, RemoveKind, RenameMode,
    };
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// 构造一个设置了 RD/CD 与自定义 opcode 的查询消息。
    fn query_msg_with_flags() -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.metadata.checking_disabled = true;
        msg.metadata.op_code = OpCode::Status;
        let mut q = Query::new();
        q.set_name(Name::from_utf8("flags.example.com").unwrap());
        q.set_query_type(RecordType::A);
        q.set_query_class(hickory_proto::rr::DNSClass::IN);
        msg.queries.push(q);
        msg
    }

    #[test]
    fn test_response_preserves_request_flags() {
        let msg = query_msg_with_flags();
        let resp = make_response_base(&msg).unwrap();

        // 请求的 flags（opcode + RD/CD）必须保留，不被服务端清除。
        assert_eq!(resp.metadata.id, msg.metadata.id);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.op_code, msg.metadata.op_code);
        assert!(resp.metadata.recursion_desired, "RD must be copied from request");
        assert!(resp.metadata.checking_disabled, "CD must be copied from request");
        // RA 由服务端设置；AA/AD 不复制。
        assert!(resp.metadata.recursion_available);
        assert!(!resp.metadata.authoritative);
        assert!(!resp.metadata.authentic_data);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn test_servfail_preserves_request_flags() {
        let msg = query_msg_with_flags();
        let resp = build_servfail(&msg);

        assert_eq!(resp.metadata.id, msg.metadata.id);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.op_code, msg.metadata.op_code);
        assert!(resp.metadata.recursion_desired, "RD must be copied from request");
        assert!(resp.metadata.checking_disabled, "CD must be copied from request");
        assert!(resp.metadata.recursion_available);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(resp.queries.len(), 1);
    }

    #[tokio::test]
    async fn test_cache_upstream_response_nodata_a() {
        let cache = DnsCache::new_metric(10, 60, 3600, false);
        let key = CacheKey::new("nodata.example.com", RecordType::A);
        // 上游返回 NOERROR 空应答（NoData）
        let mut resp = make_query_msg("nodata.example.com", RecordType::A).unwrap();
        resp.metadata.response_code = ResponseCode::NoError;

        cache_upstream_response(&cache, &key, &resp, None).await;

        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            assert_eq!(entry.records.len(), 1);
            assert!(matches!(entry.records[0], CacheRecord::NoData));
            // 从缓存重建应答：NOERROR、无 answer
            let rebuilt = build_response_from_cache(&resp, &entry, false).unwrap();
            assert!(rebuilt.answers.is_empty());
            assert_eq!(rebuilt.metadata.response_code, ResponseCode::NoError);
        } else {
            panic!("expected Fresh NoData entry");
        }
    }

    #[tokio::test]
    async fn test_cache_upstream_response_nodata_for_mx_and_https() {
        for (name, qtype) in [
            ("mx.example.com", RecordType::MX),
            ("https.example.com", RecordType::HTTPS),
        ] {
            let cache = DnsCache::new_metric(10, 60, 3600, false);
            let key = CacheKey::new(name, qtype);
            // 上游返回 NOERROR 空应答（NoData）
            let mut resp = make_query_msg(name, qtype).unwrap();
            resp.metadata.response_code = ResponseCode::NoError;

            cache_upstream_response(&cache, &key, &resp, None).await;

            // 所有类型（MX/HTTPS 等）的空应答都做 NoData 负缓存
            if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
                assert_eq!(entry.records.len(), 1);
                assert!(matches!(entry.records[0], CacheRecord::NoData));
                let rebuilt = build_response_from_cache(&resp, &entry, false).unwrap();
                assert!(rebuilt.answers.is_empty());
                assert_eq!(rebuilt.metadata.response_code, ResponseCode::NoError);
            } else {
                panic!("expected Fresh NoData entry for {qtype}");
            }
        }
    }

    #[test]
    fn test_parse_name_accepts_underscore_label() {
        // CNAME target 中间 label 含下划线（如 `path3_new.qcomgeo2.com`）时，
        // `Name::from_utf8`（IDNA/STD3）会拒绝；`parse_name` 需回退到
        // `from_ascii` 成功解析，否则 resolve_cname 无法处理此类 target。
        let n = parse_name("path3_new.qcomgeo2.com.").expect("underscore label must parse");
        assert_eq!(n.to_string(), "path3_new.qcomgeo2.com.");

        // 常规域名仍走严格 IDNA 路径，行为不变（非 FQDN 输入不加尾点）。
        assert_eq!(parse_name("www.example.com").unwrap().to_string(), "www.example.com");
        // 非法字符（空格/控制符）仍被拒绝。
        assert!(parse_name("bad name.com").is_err());
        assert!(parse_name("bad\nname.com").is_err());
    }

    #[test]
    fn test_is_change_event_write_completion_only() {
        // 原地覆写过程中间的每次数据写入（truncate / 分块写）不应触发重载，
        // 只有关闭写入句柄（Close(Write)）才表示内容写完。
        assert!(!is_change_event(&EventKind::Modify(ModifyKind::Data(DataChange::Any))));
        assert!(is_change_event(&EventKind::Access(AccessKind::Close(AccessMode::Write))));

        // 原子 rename 替换（mv tmp → target）是完整内容的落地信号。
        assert!(is_change_event(&EventKind::Modify(ModifyKind::Name(RenameMode::From))));
        assert!(is_change_event(&EventKind::Modify(ModifyKind::Name(RenameMode::To))));
        assert!(is_change_event(&EventKind::Modify(ModifyKind::Name(RenameMode::Both))));

        // 新建/删除文件仍触发；只读关闭、元数据、打开不触发。
        assert!(is_change_event(&EventKind::Create(CreateKind::File)));
        assert!(is_change_event(&EventKind::Remove(RemoveKind::File)));
        assert!(!is_change_event(&EventKind::Access(AccessKind::Close(AccessMode::Read))));
        assert!(!is_change_event(&EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any))));
        assert!(!is_change_event(&EventKind::Access(AccessKind::Open(AccessMode::Any))));
    }

    /// 复现「第一次修改正常重载、第二次起失效」：写入方通过 rename 替换文件
    /// （`sed -i` / 编辑器保存 / `mv tmp target`）时，直接监视文件本身会在第一次
    /// 替换后随旧 inode 一起被内核摘除。`watch_file` 改看父目录，必须每次都能触发。
    #[tokio::test]
    async fn test_watch_file_survives_rename_replacement() {
        let dir = std::env::temp_dir().join(format!("rsdns-watchtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("domains.txt");
        std::fs::write(&target, "one.example\n").unwrap();

        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let cb_hits = hits.clone();
        let cb_seen = seen.clone();
        let cb_target = target.clone();
        watch_file(&target, move || {
            let content = std::fs::read_to_string(&cb_target).unwrap_or_default();
            cb_seen.lock().push(content.trim().to_string());
            cb_hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        // 前几次修改用 rename 替换（原实现只会在第一次生效），最后一次原地追加。
        for n in 1..=3 {
            let tmp = dir.join(format!("domains.txt.tmp{n}"));
            std::fs::write(&tmp, format!("edit{n}.example\n")).unwrap();
            std::fs::rename(&tmp, &target).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&target).unwrap();
            f.write_all(b"edit4.example\n").unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let observed = seen.lock().clone();
        assert!(
            observed.iter().any(|c| c.contains("edit2.example")),
            "第二次修改必须触发重载，实际观察到: {observed:?}"
        );
        assert!(
            observed.iter().any(|c| c.contains("edit3.example")),
            "第三次修改必须触发重载，实际观察到: {observed:?}"
        );
        assert!(
            observed.iter().any(|c| c.contains("edit4.example")),
            "原地追加必须触发重载，实际观察到: {observed:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
