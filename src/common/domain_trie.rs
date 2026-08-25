use fst::{Map, MapBuilder};
use std::collections::{BTreeMap, HashMap};

pub type TagId = u32;

pub struct DomainSuffixTrieBuilder {
    items: BTreeMap<Vec<u8>, TagId>,
    tag_to_id: HashMap<Box<str>, TagId>,
    id_to_tag: Vec<Box<str>>,
}

impl Default for DomainSuffixTrieBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSuffixTrieBuilder {
    pub fn new() -> Self {
        Self {
            items: BTreeMap::new(),
            tag_to_id: HashMap::new(),
            id_to_tag: Vec::new(),
        }
    }

    /// 核心逻辑：将域名反转并转换为字节序列
    #[inline]
    fn reverse_domain_bytes(domain: &str) -> Vec<u8> {
        let mut parts: Vec<&str> = domain.trim_matches('.').split('.').collect();
        parts.reverse();

        // 预计算长度，减少分配次数
        let len = parts.iter().map(|p| p.len()).sum::<usize>() + parts.len().saturating_sub(1);
        let mut result = Vec::with_capacity(len);

        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                result.push(b'.');
            }
            result.extend_from_slice(part.as_bytes());
        }
        result
    }

    pub fn insert(&mut self, domain: &str, tag: &str) {
        let tag_id = self.intern_tag(tag);
        let reversed_bytes = Self::reverse_domain_bytes(domain);

        // 直接存入 BTreeMap，保持字节序排列
        self.items.insert(reversed_bytes, tag_id);
    }

    fn intern_tag(&mut self, tag: &str) -> TagId {
        if let Some(&id) = self.tag_to_id.get(tag) {
            return id;
        }
        let id = self.id_to_tag.len() as TagId;
        let boxed: Box<str> = tag.into();
        self.tag_to_id.insert(boxed.clone(), id);
        self.id_to_tag.push(boxed);
        id
    }

    pub fn build(mut self) -> Result<DomainSuffixTrie, fst::Error> {
        let mut map_builder = MapBuilder::memory();
        let items = std::mem::take(&mut self.items);
        for (key, value) in items {
            map_builder.insert(key, value as u64)?;
        }

        let map_data = map_builder.into_inner()?;

        Ok(DomainSuffixTrie {
            map: Map::new(map_data)?,
            id_to_tag: self.id_to_tag.into_boxed_slice(),
        })
    }
}

#[derive(Debug)]
pub struct DomainSuffixTrie {
    // 核心 FST 存储
    map: Map<Vec<u8>>,
    // 标签索引表
    id_to_tag: Box<[Box<str>]>,
}

impl Default for DomainSuffixTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSuffixTrie {
    pub fn new() -> Self {
        let empty_map = Map::default();
        Self {
            map: empty_map,
            id_to_tag: Box::new([]),
        }
    }
    fn lookup_big(&self, domain: &str) -> Option<&str> {
        // 预处理
        let domain = domain.trim_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }

        let rev_labels: Vec<&str> = domain.rsplit('.').collect();
        let rev_domain = rev_labels.join(".");
        let rev_bytes = rev_domain.as_bytes();

        let mut last_match = None;

        // 扫描前缀匹配
        for i in 0..rev_bytes.len() {
            if i == rev_bytes.len() - 1 || rev_bytes[i + 1] == b'.' {
                if let Some(id) = self.map.get(&rev_bytes[..=i]) {
                    last_match = Some(id);
                }
            }
        }
        last_match.and_then(|id| self.id_to_tag.get(id as usize).map(|s| s.as_ref()))
    }

    pub fn lookup(&self, domain: &str) -> Option<&str> {
        let domain = domain.trim_matches('.');
        if domain.is_empty() {
            return None;
        }

        // 使用栈分配的小缓冲区（适配常见长度的域名）
        let mut buf = [0u8; 256];
        let bytes = domain.as_bytes();
        let len = bytes.len();

        if len > 256 {
            return self.lookup_big(domain);
        } // 极长域名降级处理

        let mut pos = 0;
        for part in domain.rsplit('.') {
            if pos > 0 {
                buf[pos] = b'.';
                pos += 1;
            }
            let part_bytes = part.as_bytes();
            let end = pos + part_bytes.len();
            buf[pos..end].copy_from_slice(part_bytes);
            pos = end;
        }

        let search_target = &buf[..pos];
        let mut last_match = None;

        for i in 0..search_target.len() {
            if i == search_target.len() - 1 || search_target[i + 1] == b'.' {
                if let Some(id) = self.map.get(&search_target[..=i]) {
                    last_match = Some(id);
                }
            }
        }

        last_match.and_then(|id| self.id_to_tag.get(id as usize).map(|s| s.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_trie_lookup_miss() {
        // 空初始化测试：创建空的 trie，查询任意域名应返回 None
        let builder = DomainSuffixTrieBuilder::new();
        let trie = builder.build().unwrap();

        assert!(trie.lookup("example.com").is_none(), "空 trie 查询应返回 None");
        assert!(trie.lookup("sub.example.com").is_none());
        assert!(trie.lookup("any.domain.test").is_none());
    }

    #[test]
    fn test_lookup_match() {
        // 匹配测试：插入域名规则后，查询匹配域名应命中
        let mut builder = DomainSuffixTrieBuilder::new();
        builder.insert("example.com", "example_tag");
        builder.insert("test.org", "test_tag");
        let trie = builder.build().unwrap();

        // 精确匹配
        assert_eq!(trie.lookup("example.com"), Some("example_tag"), "精确域名应命中");
        assert_eq!(trie.lookup("test.org"), Some("test_tag"));

        // 子域名匹配（因为是后缀树，子域名应命中）
        assert_eq!(trie.lookup("sub.example.com"), Some("example_tag"), "子域名应命中父规则");
        assert_eq!(trie.lookup("deep.sub.example.com"), Some("example_tag"), "深层子域名也应命中");
    }

    #[test]
    fn test_lookup_mismatch() {
        // 不匹配测试：插入规则后，查询不相关域名应未命中
        let mut builder = DomainSuffixTrieBuilder::new();
        builder.insert("example.com", "example_tag");
        let trie = builder.build().unwrap();

        // 完全不相关域名
        assert!(trie.lookup("other.com").is_none(), "不相关域名应未命中");
        assert!(trie.lookup("example.org").is_none(), "不同 TLD 应未命中");
        assert!(trie.lookup("test.com").is_none(), "不同二级域名应未命中");

        // 边界情况
        assert!(trie.lookup("exampl.com").is_none(), "近似域名应未命中");
        assert!(trie.lookup("example.co").is_none(), "不同后缀应未命中");
    }
}
