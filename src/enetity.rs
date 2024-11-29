use std::{error::Error, str};

use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::tools::{decode_base64, decode_url_param};
#[derive(Deserialize)]
pub struct SubInput {
    pub target: String,
    pub rule_config: String,
    pub source: String,
}
#[derive(Debug)]
pub struct RespInfo {
    pub code: u16,
    pub body: String,
}
#[derive(Debug)]
pub struct Proxy {
    pub name: String,
    pub proxy_type: ProxyType,
    pub sub_data: Mapping,
}

impl Proxy {
    pub fn from_str(link_str: &str) -> Result<Proxy, Box<dyn Error>> {
        let mut type_link = link_str.split("://");
        let proxy_type = ProxyType::from_str(type_link.next().ok_or("")?)
            .ok_or("未知的代理类型：目前只支持trojan/ss")?;
        let sub_data = proxy_type.parse_proxy(type_link.next().ok_or("err")?)?;
        Ok(Proxy {
            name: sub_data
                .get("name")
                .ok_or("err")?
                .as_str()
                .ok_or("err")?
                .to_string(),
            proxy_type: proxy_type,
            sub_data: sub_data,
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub enum ProxyType {
    #[serde{rename="trojan"}]
    Trojan,
    #[serde{rename="ss"}]
    SS,
}
impl ProxyType {
    pub fn parse_proxy(&self, input: &str) -> Result<Mapping, Box<dyn Error>> {
        let link_format = self.link_format();
        let re = Regex::new(&link_format)?;
        let caps: Captures<'_> = re.captures(input).ok_or("代理链接格式不符请检查")?;
        self.insert_map(caps)
    }
    fn link_format(&self) -> &str {
        match self {
            ProxyType::Trojan => {
                r"^(?P<password>.+)@(?P<address>[^:]+):(?P<port>\d+)(?:\?(?P<params>[^#]+))?(?:#(?P<remark>.+))?$"
            }
            ProxyType::SS => {
                r"^(?P<password>.+)@(?P<address>[^:]+):(?P<port>\d+)(?:\?(?P<params>[^#]+))?(?:#(?P<remark>.+))?$"
            }
        }
    }
    fn insert_map(&self, caps: Captures<'_>) -> Result<Mapping, Box<dyn Error>> {
        let mut soucrces: Mapping = Mapping::new();
        match self {
            ProxyType::Trojan => {
                soucrces.insert(
                    Value::from("name"),
                    Value::from(decode_url_param(&(caps["remark"].to_string()))),
                );
                soucrces.insert(
                    Value::from("password"),
                    Value::from(caps["password"].to_string()),
                );
                soucrces.insert(
                    Value::from("server"),
                    Value::from(caps["address"].to_string()),
                );
                soucrces.insert(Value::from("port"), Value::from(caps["port"].parse::<u32>()?));
                soucrces.insert(Value::from("skip-cert-verify"), Value::from(false));
            }
            ProxyType::SS => {
                let d_p_c = decode_base64(caps["password"].to_string().as_str())?;
                let mut cipher_pass = d_p_c.split(":");
                soucrces.insert(
                    Value::from("name"),
                    Value::from(decode_url_param(&(caps["remark"].to_string()))),
                );
                soucrces.insert(
                    Value::from("cipher"),
                    Value::from(
                        cipher_pass
                            .next()
                            .ok_or("解析ss类型失败-cipher")?
                            .to_string(),
                    ),
                );
                soucrces.insert(
                    Value::from("password"),
                    Value::from(
                        cipher_pass
                            .next()
                            .ok_or("解析ss类型失败-password")?
                            .to_string(),
                    ),
                );
                soucrces.insert(
                    Value::from("server"),
                    Value::from(caps["address"].to_string()),
                );
                soucrces.insert(Value::from("port"), Value::from(caps["port"].parse::<u32>()?));
                
            }
        }
        soucrces.insert(Value::from("udp"), Value::from(true));
        soucrces.insert(Value::from("type"), Value::from(self.as_str()));
        Ok(soucrces)
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trojan" => Some(ProxyType::Trojan),
            "ss" => Some(ProxyType::SS),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            ProxyType::Trojan => "trojan",
            ProxyType::SS => "ss",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleGroup {
    #[serde{rename="name"}]
    pub group_name: String,
    #[serde{rename="type"}]
    pub group_type: String,
    pub proxies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Dns {
    pub enabled: bool,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClashProxyConfig {
    pub port: u32,
    #[serde{rename="socks-port"}]
    pub socks_port: u32,
    #[serde{rename="allow-lan"}]
    pub allow_lan: bool,
    pub mode: String,
    #[serde{rename="log-level"}]
    pub log_level: String,
    #[serde{rename="external-controller"}]
    pub external_controller: String,
    pub dns: Dns,
    pub proxies: Vec<Mapping>,
    #[serde{rename="proxy-groups"}]
    pub proxy_groups: Vec<RuleGroup>,
    pub rules: Vec<String>,
}