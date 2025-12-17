//! # 规则文件管理器
//!
//! 负责规则文件的初始化、读取和追加操作。

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use super::formatter::{create_formatter, OutputFormat, Rule};

/// 规则文件管理器
pub struct RuleFileManager {
    /// 配置目录
    config_dir: PathBuf,
}

impl RuleFileManager {
    /// 创建新的管理器实例
    pub fn new() -> Result<Self> {
        let home = std::env::var("HOME").context("Failed to get HOME directory")?;
        let config_dir = PathBuf::from(format!("{}/.config/proxy-audit", home));

        // 确保配置目录存在
        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        Ok(Self { config_dir })
    }

    /// 获取指定格式和策略的规则文件路径
    pub fn get_rule_file_path(
        &self,
        format: OutputFormat,
        policy: super::formatter::RulePolicy,
    ) -> PathBuf {
        let policy_str = match policy {
            super::formatter::RulePolicy::Direct => "direct",
            super::formatter::RulePolicy::Proxy => "proxy",
            super::formatter::RulePolicy::Reject => "reject",
        };

        let filename = match format {
            OutputFormat::Clash => format!("rules-{}.yaml", policy_str),
            OutputFormat::Surge => format!("rules-{}.list", policy_str),
            OutputFormat::QuantumultX => format!("rules-{}.list", policy_str),
            OutputFormat::SingBox => format!("rules-{}.json", policy_str),
        };
        self.config_dir.join(filename)
    }

    /// 初始化规则文件
    pub fn init(&self, format: OutputFormat) -> Result<String> {
        let policies = [
            super::formatter::RulePolicy::Direct,
            super::formatter::RulePolicy::Proxy,
            super::formatter::RulePolicy::Reject,
        ];

        let formatter = create_formatter(format);

        for policy in policies {
            let path = self.get_rule_file_path(format, policy);
            // 如果文件不存在，创建空文件
            if !path.exists() {
                let empty_content = formatter.generate_file_content(&[]);
                fs::write(&path, &empty_content)?;
                println!("Created rule file: {}", path.display());
            } else {
                println!("Rule file already exists: {}", path.display());
            }
        }

        // 返回引导配置
        Ok(formatter.generate_guide(&self.config_dir.to_string_lossy()))
    }

    /// 添加单条进程规则（Process Name based）
    pub fn add_rule(
        &self,
        pid: i32,
        policy: super::formatter::RulePolicy,
        format: OutputFormat,
    ) -> Result<()> {
        // 1. 获取进程名 (via libproc)
        let process_name = crate::macos::libproc::get_process_name(pid)
            .context(format!("Failed to get process name for PID {}", pid))?;

        if process_name.is_empty() {
            anyhow::bail!("PID {} not found or has no name.", pid);
        }

        println!("Found process: {} (PID: {})", process_name, pid);

        // 2. QX 不支持 ProcessName，需特殊处理
        if format == OutputFormat::QuantumultX {
            println!("Warning: Quantumult X does not support process-name rules via this tool.");
            return Ok(());
        }

        // 3. 加载所有策略文件并清理冲突
        let policies = [
            super::formatter::RulePolicy::Direct,
            super::formatter::RulePolicy::Proxy,
            super::formatter::RulePolicy::Reject,
        ];

        let formatter = create_formatter(format);

        for p in policies {
            let path = self.get_rule_file_path(format, p);
            let mut rules = if path.exists() {
                self.read_rules(format, p)?
            } else {
                Vec::new()
            };

            // 移除当前进程名的旧规则
            let initial_len = rules.len();
            rules.retain(|r| {
                !(matches!(r.rule_type, super::formatter::RuleType::ProcessName)
                    && r.value == process_name)
            });

            // 如果是目标策略，则添加新规则
            if p == policy {
                rules.push(Rule {
                    rule_type: super::formatter::RuleType::ProcessName,
                    value: process_name.clone(),
                    policy: p,
                });
            }

            // 只有当内容发生变化（原有被删 或者 新增了）才写入
            // 但为了简单，只要是目标文件肯定变了，非目标文件如果删了也变了
            // 简单点：全部重写对应的文件
            let content = formatter.generate_file_content(&rules);
            fs::write(&path, content)?;

            if p == policy {
                println!("Added rule to {}", path.display());
            } else if rules.len() < initial_len {
                println!("Removed conflicting rule from {}", path.display());
            }
        }

        Ok(())
    }

    /// 生成单条规则字符串（不写入文件）
    pub fn generate_rule(
        &self,
        pid: i32,
        policy: super::formatter::RulePolicy,
        format: OutputFormat,
    ) -> Result<String> {
        let process_name = crate::macos::libproc::get_process_name(pid)
            .context(format!("Failed to get process name for PID {}", pid))?;

        let rule = Rule {
            rule_type: super::formatter::RuleType::ProcessName,
            value: process_name,
            policy,
        };

        let formatter = create_formatter(format);
        formatter
            .format_rule(&rule)
            .context("This format does not support process-name rules.")
    }

    // append_rules 已被 add_rule 的逻辑取代，这里移除它或者改为私有辅助（暂且移除）

    /// 读取现有规则
    fn read_rules(
        &self,
        format: OutputFormat,
        policy: super::formatter::RulePolicy,
    ) -> Result<Vec<Rule>> {
        let path = self.get_rule_file_path(format, policy);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path)?;

        // 根据格式解析规则
        match format {
            OutputFormat::Clash => self.parse_clash_rules(&content, policy),
            OutputFormat::Surge => self.parse_surge_rules(&content, policy),
            OutputFormat::QuantumultX => self.parse_qx_rules(&content, policy),
            OutputFormat::SingBox => self.parse_singbox_rules(&content, policy),
        }
    }

    /// 解析 Clash 格式规则
    fn parse_clash_rules(
        &self,
        content: &str,
        policy: super::formatter::RulePolicy,
    ) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("- ") {
                if let Some(rule) = self.parse_clash_rule_line(&line[2..], policy) {
                    rules.push(rule);
                }
            }
        }

        Ok(rules)
    }

    /// 解析单条 Clash 规则行 (V2: 只有 TYPE,VALUE，没有 POLICY)
    fn parse_clash_rule_line(
        &self,
        line: &str,
        policy: super::formatter::RulePolicy,
    ) -> Option<Rule> {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let rule_type = match parts[0].trim() {
                "IP-CIDR" => super::formatter::RuleType::IpCidr,
                "DOMAIN-SUFFIX" => super::formatter::RuleType::DomainSuffix,
                "DOMAIN" => super::formatter::RuleType::Domain,
                "PROCESS-NAME" => super::formatter::RuleType::ProcessName,
                _ => return None,
            };
            let value = parts[1].trim().to_string();
            // policy 由参数传入（基于文件名）
            return Some(Rule {
                rule_type,
                value,
                policy,
            });
        }
        None
    }

    /// 解析 Surge 格式规则
    fn parse_surge_rules(
        &self,
        content: &str,
        policy: super::formatter::RulePolicy,
    ) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Surge 格式与 Clash 类似 (TYPE,VALUE)
            if let Some(rule) = self.parse_clash_rule_line(line, policy) {
                rules.push(rule);
            }
        }

        Ok(rules)
    }

    /// 解析 Quantumult X 格式规则
    fn parse_qx_rules(
        &self,
        content: &str,
        policy: super::formatter::RulePolicy,
    ) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let rule_type = match parts[0].to_lowercase().as_str() {
                    "ip-cidr" => super::formatter::RuleType::IpCidr,
                    "host-suffix" => super::formatter::RuleType::DomainSuffix,
                    "host" => super::formatter::RuleType::Domain,
                    _ => continue,
                };
                let value = parts[1].to_string();
                // QX 可能在文件里有 policy，也可能没有。为了统一，我们这里信任文件名对应的 policy
                // 也可以尝试解析 parts[2] 但我们主要关注 overwrite 逻辑
                rules.push(Rule {
                    rule_type,
                    value,
                    policy,
                });
            }
        }

        Ok(rules)
    }

    /// 解析 Sing-box 格式规则
    fn parse_singbox_rules(
        &self,
        content: &str,
        policy: super::formatter::RulePolicy,
    ) -> Result<Vec<Rule>> {
        let json: serde_json::Value = serde_json::from_str(content).unwrap_or_default();
        let mut rules = Vec::new();

        if let Some(rules_array) = json.get("rules").and_then(|r| r.as_array()) {
            for rule_obj in rules_array {
                // 不再读取 outbound，直接使用传入的 policy

                // 处理 IP-CIDR
                if let Some(ip_cidrs) = rule_obj.get("ip_cidr").and_then(|v| v.as_array()) {
                    for ip in ip_cidrs {
                        if let Some(ip_str) = ip.as_str() {
                            rules.push(Rule {
                                rule_type: super::formatter::RuleType::IpCidr,
                                value: ip_str.to_string(),
                                policy,
                            });
                        }
                    }
                }

                // 处理 Process Name
                if let Some(process_names) = rule_obj.get("process_name").and_then(|v| v.as_array())
                {
                    for name in process_names {
                        if let Some(name_str) = name.as_str() {
                            rules.push(Rule {
                                rule_type: super::formatter::RuleType::ProcessName,
                                value: name_str.to_string(),
                                policy,
                            });
                        }
                    }
                }
            }
        }

        Ok(rules)
    }
}
