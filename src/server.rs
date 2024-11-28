use crate::{constant, tools};
use std::error::Error;

use super::enetity::*;
use regex::Regex;
use reqwest::Client;
use serde_yaml::{self, Mapping};
use unicode_normalization::UnicodeNormalization;

pub async fn sub_server(data: SubInput) -> RespInfo {
    //解析原本代理信息
    let proxies: Vec<Proxy> = match analyze_source(&data.source).await {
        Ok(proxies) => proxies,
        Err(err) => {
            return RespInfo {
                code: 500,
                body: err.to_string(),
            }
        }
    };
    let proxies_name: Vec<String> = proxies.iter().map(|p| p.name.clone()).collect();
    //解析规则模板文件
    let (groups, rules) = match analyze_rule_template(&data.rule_config, &proxies_name).await {
        Ok(template) => template,
        Err(err) => {
            return RespInfo {
                code: 500,
                body: err.to_string(),
            }
        }
    };
    let coll_sub_data: Vec<Mapping> =
        proxies.iter().map(|item| item.sub_data.clone()).collect();
    let clash_config: ClashProxyConfig = generate_clash(coll_sub_data, groups, rules);
    RespInfo {
        code: 200,
        body: match serde_yaml::to_string(&clash_config) {
            Ok(clash_config) => clash_config,
            Err(err) => {
                return RespInfo {
                    code: 500,
                    body: err.to_string(),
                }
            }
        },
    }
}

fn generate_clash(
    coll_sub_data: Vec<Mapping>,
    groups: Vec<RuleGroup>,
    rules: Vec<String>,
) -> ClashProxyConfig {
    ClashProxyConfig {
        port: constant::clash_constant::PORT,
        socks_port: constant::clash_constant::SOCKS_PORT,
        allow_lan: constant::clash_constant::ALLOW_LAN,
        mode: constant::clash_constant::MODE.to_string(),
        log_level: constant::clash_constant::LOG_LEVEL.to_string(),
        external_controller: constant::clash_constant::EXTERNAL_CONTROLLER,
        dns: Dns {
            enabled: constant::clash_constant::DNS_ENABLED,
            nameserver: constant::clash_constant::DNS_NAMESERVER
                .iter()
                .map(|i| i.to_string().clone())
                .collect(),
            fallback: constant::clash_constant::DNS_FALLBACK
                .iter()
                .map(|i| i.to_string().clone())
                .collect(),
        },
        proxies: coll_sub_data,
        proxy_groups: groups,
        rules: rules,
    }
}

async fn analyze_rule_template(
    rule_config_path: &String,
    proxies_name: &Vec<String>,
) -> Result<(Vec<RuleGroup>, Vec<String>), Box<dyn Error>> {
    let client = Client::new();
    let rule_config = client.get(rule_config_path).send().await?.text().await?;
    let group_rules: Vec<&str> = rule_config
        .lines()
        .map(|m| m.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with(';'))
        .collect();
    let mut rule_grpups: Vec<RuleGroup> = Vec::new();
    let mut rules: Vec<String> = Vec::new();
    for g_or_r in group_rules {
        let mut r_or_g_s = g_or_r.split("=");
        let mut ini_format_err = String::from("ini配置文件格式错误,错误行内容:");
        ini_format_err.push_str(&g_or_r);

        let _ = match r_or_g_s.next().ok_or(ini_format_err.as_str())? {
            "ruleset" => {
                save_rules(
                    r_or_g_s.next().ok_or(ini_format_err.as_str())?,
                    &mut rules,
                    &client,
                )
                .await
            }
            "custom_proxy_group" => Ok(rule_grpups.push(save_group(
                r_or_g_s.next().ok_or(ini_format_err.as_str())?,
                &proxies_name,
            )?)),
            _ => Ok(()),
        };
    }
    Ok((rule_grpups, rules))
}

async fn save_rules(
    rule: &str,
    rules: &mut Vec<String>,
    client: &Client,
) -> Result<(), Box<dyn Error>> {
    let mut fields = rule.split(',');
    let err_ini_rule = "ini配置文件中规则格式有误:规则组,规则地址";
    let group_name = fields.next().ok_or(err_ini_rule)?;
    let rule_config = client
        .get(fields.next().ok_or(err_ini_rule)?)
        .send()
        .await?
        .text()
        .await?;
    let rule_configs: Vec<&str> = rule_config
        .lines()
        .map(|m| m.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .collect();
    for config in rule_configs {
        let mut rule_fields: Vec<&str> = config.split(',').collect();
        if rule_fields.len()>1 {
            rule_fields.insert(2, group_name);
        }else{
            rule_fields.insert(1, group_name);
        }
        
        rules.push(rule_fields.join(","));
    }
    Ok(())
}

fn save_group(group: &str, proxies_name: &Vec<String>) -> Result<RuleGroup, Box<dyn Error>> {
    let mut rule_group = RuleGroup {
        group_name: String::new(),
        group_type: String::new(),
        proxies: Vec::new(),
        url: None,
        interval: None,
        strategy: None,
    };
    for (index, field) in group.split("`").enumerate() {
        if index == 0 {
            rule_group.group_name = field.nfc().collect();
        } else if index == 1 {
            rule_group.group_type = String::from(field);
        } else if field.starts_with("http") {
            rule_group.url = Some(String::from(field))
        } else if field.parse::<u32>().is_ok() {
            rule_group.interval = Some(field.parse::<u32>()?)
        } else {
            rule_group.proxies.push(field.nfc().collect());
        }
    }
    let mut proxies_split: Vec<String> = Vec::new();
    let mut group_proxy_index: Option<usize> = None;
    for (index, group_proxy) in rule_group.proxies.iter_mut().enumerate() {
        if group_proxy.starts_with("[]") {
            *group_proxy = group_proxy.trim_start_matches("[]").to_string();
        } else {
            if !proxies_split.is_empty() {
                continue;
            }
            let regex = Regex::new(group_proxy)?;
            let p_s: Vec<String> = proxies_name
                .into_iter()
                .filter(|p| regex.is_match(p))
                .map(|item| item.to_string())
                .collect();
            proxies_split.extend(p_s);
            group_proxy_index = Some(index);
        }
    }
    match group_proxy_index {
        Some(index) => {
            rule_group.proxies.remove(index);
            rule_group.proxies.splice(index..index, proxies_split);
        }
        None => (),
    }
    Ok(rule_group)
}

async fn analyze_source(source_path: &String) -> Result<Vec<Proxy>, Box<dyn Error>> {
    let client = Client::new();
    let mut sources = client.get(source_path).send().await?.text().await?;
    sources = tools::decode_base64(&sources)?;
    let mut proxies: Vec<Proxy> = Vec::new();
    for line in sources.lines() {
        proxies.push(Proxy::from_str(line)?);
    }
    Ok(proxies)
}
#[cfg(test)]
mod tests {
    use unicode_normalization::UnicodeNormalization;

    use crate::{
        server::{sub_server,SubInput},
        tools::decode_base64,
    };

    use super::{analyze_rule_template, analyze_source, Proxy};
    #[tokio::test]
    async fn test_sub_server() {
        let sub_input = SubInput{ target: "clash".to_string(), rule_config: "https://raw.githubusercontent.com/pitfall-a/ruleClash/refs/heads/main/config.ini".to_string(), source: "https://linka.lmscunb.cc:2087/api/v1/client/subscribe?token=79592b32b1b77c402eeed56f9ce1ca92".to_string() };
        let response = sub_server(sub_input).await;
        println!("{}",response.code);
        println!("{}",response.body);
    }

    #[tokio::test]
    async fn test_analyze_template() {
        let path = "https://raw.githubusercontent.com/pitfall-a/ruleClash/refs/heads/main/config.ini".to_string();
        let proxies = vec!["美国 02".to_string(),"美国 08".to_string()];
        match analyze_rule_template(&path, &proxies).await {
            Ok((group,rules)) => println!("Error occurred: {:?},{:?}", group,rules),
            Err(e) => println!("Error occurred: {}", e),
        }
    }


    #[tokio::test]
    async fn test_analyze_source() {
        let source_path = String::from("https://linka.lmscunb.cc:2087/api/v1/client/subscribe?token=79592b32b1b77c402eeed56f9ce1ca92");
        match analyze_source(&source_path).await {
            Ok(result) => println!("Analyze result: {:?}", result),
            Err(e) => println!("Error occurred: {}", e),
        }
    }

    #[test]
    fn test_decode_base64() {
        let pass_type =
            decode_base64("YWVzLTEyOC1nY206MDMxYzJjMDgtYjliYy00YjMwLTgxNjQtMzkzYzU4YTNjYTRi")
                .unwrap();
        let mut pass_cipher = pass_type.split(":");
        println!("{}", pass_cipher.next().ok_or("efefeef").unwrap());
        println!("{}", pass_cipher.next().ok_or("efefeef").unwrap());
    }

    #[test]
    fn test_enum_type() {
        let proxy = Proxy::from_str("trojan://031c2c08-b9bc-4b30-8164-393c58a3ca4b@lmnode-ixd3fh2v5uqlv3z-lmhk.lma1b2.com:53401?allowInsecure=1#%E6%9C%80%E6%96%B0%E7%BD%91%E5%9D%80%EF%BC%9Almspeed.co").unwrap();
        println!("{:?}", proxy.sub_data);
    }
    #[test]
    fn test_emoji(){
        let emo:String = "♻\u{fe0f} 自动选择".nfc().collect();
        println!("{}",emo)
    }
}
