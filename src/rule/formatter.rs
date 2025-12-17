//! # 规则格式化器
//!
//! 定义规则数据结构和多平台格式化输出。

use std::fmt;

use serde::{Deserialize, Serialize};

/// 规则策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RulePolicy {
    /// 直连（不走代理）
    Direct,
    /// 走代理
    Proxy,
    /// 拒绝连接
    Reject,
}

impl fmt::Display for RulePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulePolicy::Direct => write!(f, "DIRECT"),
            RulePolicy::Proxy => write!(f, "PROXY"),
            RulePolicy::Reject => write!(f, "REJECT"),
        }
    }
}

impl Default for RulePolicy {
    fn default() -> Self {
        RulePolicy::Direct
    }
}

/// 输出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Clash / Clash Meta
    Clash,
    /// Surge
    Surge,
    /// Quantumult X
    QuantumultX,
    /// Sing-box
    SingBox,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Clash => write!(f, "clash"),
            OutputFormat::Surge => write!(f, "surge"),
            OutputFormat::QuantumultX => write!(f, "quantumultx"),
            OutputFormat::SingBox => write!(f, "sing-box"),
        }
    }
}

/// 单条分流规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// 规则类型 (IP-CIDR, DOMAIN-SUFFIX 等)
    pub rule_type: RuleType,
    /// 规则值 (IP 地址或域名)
    pub value: String,
    /// 策略
    pub policy: RulePolicy,
}

/// 规则类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// IP-CIDR 规则
    IpCidr,
    /// 域名后缀规则
    DomainSuffix,
    /// 精确域名规则
    Domain,
    /// 进程名规则
    ProcessName,
}

/// 规则格式化 trait
pub trait Formatter {
    /// 格式化单条规则
    fn format_rule(&self, rule: &Rule) -> Option<String>;

    /// 格式化多条规则
    fn format_rules(&self, rules: &[Rule]) -> String {
        rules
            .iter()
            .filter_map(|r| self.format_rule(r))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 获取规则文件扩展名
    fn file_extension(&self) -> &'static str;

    /// 生成规则文件内容（包含必要的文件头）
    fn generate_file_content(&self, rules: &[Rule]) -> String;

    /// 生成引导配置（用于 init 命令）
    fn generate_guide(&self, rule_file_path: &str) -> String;
}

// ========================================
// Clash 格式化器
// ========================================

pub struct ClashFormatter;

impl Formatter for ClashFormatter {
    fn format_rule(&self, rule: &Rule) -> Option<String> {
        let type_str = match rule.rule_type {
            RuleType::IpCidr => "IP-CIDR",
            RuleType::DomainSuffix => "DOMAIN-SUFFIX",
            RuleType::Domain => "DOMAIN",
            RuleType::ProcessName => "PROCESS-NAME",
        };

        // IP-CIDR 需要加 /32
        let value = if matches!(rule.rule_type, RuleType::IpCidr) && !rule.value.contains('/') {
            format!("{}/32", rule.value)
        } else {
            rule.value.clone()
        };

        // V2 Update: 不再输出策略 (Policy)，由外部 Rule Provider 决定
        // Example: "  - PROCESS-NAME,Telegram"
        Some(format!("  - {},{}", type_str, value))
    }

    fn file_extension(&self) -> &'static str {
        "yaml"
    }

    fn generate_file_content(&self, rules: &[Rule]) -> String {
        if rules.is_empty() {
            return String::from("# proxy-audit generated rules\npayload: []\n");
        }

        let mut content = String::from("# proxy-audit generated rules\npayload:\n");
        for rule in rules {
            if let Some(line) = self.format_rule(rule) {
                content.push_str(&line);
                content.push('\n');
            }
        }
        content
    }

    fn generate_guide(&self, config_dir: &str) -> String {
        format!(
            r#"# ============================================================
# Clash 配置指南 (Policy-Based)
# ============================================================
# 请将以下内容添加到您的 Clash 配置文件中：

# 1. 在 rule-providers 段添加：
rule-providers:
  proxy-audit-direct:
    type: file
    behavior: classical
    path: "{}/rules-direct.yaml"
  proxy-audit-proxy:
    type: file
    behavior: classical
    path: "{}/rules-proxy.yaml"
  proxy-audit-reject:
    type: file
    behavior: classical
    path: "{}/rules-reject.yaml"

# 2. 在 rules 段添加（放在其他规则之前）：
rules:
  - RULE-SET,proxy-audit-direct,DIRECT
  - RULE-SET,proxy-audit-reject,REJECT
  # 注意: 请将 'PROXY' 替换为您配置文件中实际的 代理策略组名称 (例如 'Proxy', '节点选择', '🚀 节点选择' 等)
  - RULE-SET,proxy-audit-proxy,PROXY
  # ... 您的其他规则 ...

# ============================================================
# 配置完成后，重载 Clash 配置即可生效。
# 之后使用 `proxy-audit rule add` 添加规则会自动更新对应的文件。
# ============================================================
"#,
            config_dir, config_dir, config_dir
        )
    }
}

// ========================================
// Surge 格式化器
// ========================================

pub struct SurgeFormatter;

impl Formatter for SurgeFormatter {
    fn format_rule(&self, rule: &Rule) -> Option<String> {
        let type_str = match rule.rule_type {
            RuleType::IpCidr => "IP-CIDR",
            RuleType::DomainSuffix => "DOMAIN-SUFFIX",
            RuleType::Domain => "DOMAIN",
            RuleType::ProcessName => "PROCESS-NAME",
        };

        let value = if matches!(rule.rule_type, RuleType::IpCidr) && !rule.value.contains('/') {
            format!("{}/32", rule.value)
        } else {
            rule.value.clone()
        };

        // V2 Update: 不再输出策略
        Some(format!("{},{}", type_str, value))
    }

    fn file_extension(&self) -> &'static str {
        "list"
    }

    fn generate_file_content(&self, rules: &[Rule]) -> String {
        let mut content = String::from("# proxy-audit generated rules\n");
        for rule in rules {
            if let Some(line) = self.format_rule(rule) {
                content.push_str(&line);
                content.push('\n');
            }
        }
        content
    }

    fn generate_guide(&self, config_dir: &str) -> String {
        format!(
            r#"# ============================================================
# Surge 配置指南 (Policy-Based)
# ============================================================
# 请将以下内容添加到您的 Surge 配置文件的 [Rule] 段：

RULE-SET,{}/rules-direct.list,DIRECT
RULE-SET,{}/rules-proxy.list,PROXY
RULE-SET,{}/rules-reject.list,REJECT

# ============================================================
# 配置完成后，重载 Surge 配置即可生效。
# ============================================================
"#,
            config_dir, config_dir, config_dir
        )
    }
}

// ========================================
// Quantumult X 格式化器
// ========================================

pub struct QuantumultXFormatter;

impl Formatter for QuantumultXFormatter {
    fn format_rule(&self, rule: &Rule) -> Option<String> {
        // QX 不支持进程名规则，跳过
        if matches!(rule.rule_type, RuleType::ProcessName) {
            return None;
        }

        let type_str = match rule.rule_type {
            RuleType::IpCidr => "ip-cidr",
            RuleType::DomainSuffix => "host-suffix",
            RuleType::Domain => "host",
            RuleType::ProcessName => return None,
        };

        let value = if matches!(rule.rule_type, RuleType::IpCidr) && !rule.value.contains('/') {
            format!("{}/32", rule.value)
        } else {
            rule.value.clone()
        };

        // QX 支持本地 filter 引用，但也推荐不带策略
        Some(format!("{}, {}", type_str, value))
    }

    fn file_extension(&self) -> &'static str {
        "list"
    }

    fn generate_file_content(&self, rules: &[Rule]) -> String {
        let mut content = String::from("# proxy-audit generated rules\n");
        for rule in rules {
            if let Some(line) = self.format_rule(rule) {
                content.push_str(&line);
                content.push('\n');
            }
        }
        content
    }

    fn generate_guide(&self, rule_file_path: &str) -> String {
        format!(
            r#"# ============================================================
# Quantumult X 配置指南
# ============================================================
# 建议手动引用以下文件：
# DIRECT: {}/rules-direct.list
# PROXY:  {}/rules-proxy.list
# REJECT: {}/rules-reject.list
# ============================================================
"#,
            rule_file_path, rule_file_path, rule_file_path
        )
    }
}

// ========================================
// Sing-box 格式化器
// ========================================

pub struct SingBoxFormatter;

impl Formatter for SingBoxFormatter {
    fn format_rule(&self, rule: &Rule) -> Option<String> {
        // Sing-box 使用 JSON 格式，这里返回单条规则的 JSON
        let (key, value) = match rule.rule_type {
            RuleType::IpCidr => {
                let v = if !rule.value.contains('/') {
                    format!("{}/32", rule.value)
                } else {
                    rule.value.clone()
                };
                ("ip_cidr", v)
            }
            RuleType::DomainSuffix => ("domain_suffix", rule.value.clone()),
            RuleType::Domain => ("domain", rule.value.clone()),
            RuleType::ProcessName => ("process_name", rule.value.clone()),
        };

        // V2 Update: 不再输出 outbound
        Some(format!(r#"    {{ "{}": ["{}"] }}"#, key, value))
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }

    fn generate_file_content(&self, rules: &[Rule]) -> String {
        let rules_json: Vec<String> = rules.iter().filter_map(|r| self.format_rule(r)).collect();
        format!(
            r#"{{
  "version": 1,
  "rules": [
{}
  ]
}}"#,
            rules_json.join(",\n")
        )
    }

    fn generate_guide(&self, config_dir: &str) -> String {
        format!(
            r#"// ============================================================
// Sing-box 配置指南
// ============================================================
// 1. route.rule_set:
{{ "type": "local", "tag": "pa-direct", "path": "{}/rules-direct.json", "format": "source" }},
{{ "type": "local", "tag": "pa-proxy",  "path": "{}/rules-proxy.json",  "format": "source" }},
{{ "type": "local", "tag": "pa-reject", "path": "{}/rules-reject.json", "format": "source" }}

// 2. route.rules:
{{ "rule_set": "pa-direct", "outbound": "direct" }},
{{ "rule_set": "pa-proxy",  "outbound": "proxy" }},
{{ "rule_set": "pa-reject", "outbound": "block" }}
"#,
            config_dir, config_dir, config_dir
        )
    }
}

/// 根据格式类型创建格式化器
pub fn create_formatter(format: OutputFormat) -> Box<dyn Formatter> {
    match format {
        OutputFormat::Clash => Box::new(ClashFormatter),
        OutputFormat::Surge => Box::new(SurgeFormatter),
        OutputFormat::QuantumultX => Box::new(QuantumultXFormatter),
        OutputFormat::SingBox => Box::new(SingBoxFormatter),
    }
}
