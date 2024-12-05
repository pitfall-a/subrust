use chrono::Utc;
use flate2::{write::GzEncoder, Compression};
use sub_rust::{server::sub_server,enetity::SubInput};
use url::form_urlencoded;
use vercel_runtime::{Body, Request, Response};
use std::{error::Error, io::Write};
use vercel_runtime::run;
// 处理 GET 请求
async fn handle_get(req: Request) -> Result<Response<Body>, Box<dyn Error + Send + Sync>> {
    // 获取请求的 URI 并解析
    let query = req.uri().query().unwrap_or("");

    // 解析查询参数
    let params = parse_query_params(query)?;

    // 获取 target, rule_config 和 source 参数
    let sub_input = SubInput {
        target: params
            .get("target")
            .unwrap_or(&String::from("default_target"))
            .to_string(),
        rule_config: params
            .get("rule_config")
            .unwrap_or(&String::from("default_rule_config"))
            .to_string(),
        source: params
            .get("source")
            .unwrap_or(&String::from("default_source"))
            .to_string(),
    };
    let resp = sub_server(sub_input).await;
    
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(resp.body.as_bytes()).unwrap();
    let compressed_body = encoder.finish().unwrap();
    // 返回 200 响应
    Ok(Response::builder()
        .status(resp.code)
        .header("content-type", "text/plain;charset=utf-8")
        .header("Content-Encoding", "gzip")
        .header("access-control-allow-credentials", "true")
        .header("access-control-allow-origin", "*")
        .header("Date", Utc::now().to_rfc2822())
        .header("alt-svc", "h3=\":443\"; ma=86400")
        .header("cf-cache-status", "DYNAMIC")
        .header("cf-ray", "8eb774f57f96e3a8-NRT")
        .header("profile-update-interval", "24")
        .header("server", "cloudflare")
        .header("strict-transport-security", "max-age=31536000")
        .header("subscription-userinfo", "upload=0; download=1; total=1;")
        .header("vary", "Accept-Encoding")
        .header("report-to", "{\"endpoints\":[{\"url\":\"https:\\/\\/a.nel.cloudflare.com\\/report\\/v4?s=d%2BThOXr5KeHdjk4%2BcGkNl9AzF7DaJoeot68JiAICHD9ELjIlVN4quOevuQDAig9UE6ztpR1Rd4TLLnwjiEeUn9DGK3RY4MzkIe3yWmqXEDqgZfOgfeeMm2u1kH8%3D\"}],\"group\":\"cf-nel\",\"max_age\":604800}")
        .header("server-timing", "cfL4;desc=\"?proto=TCP&rtt=570&min_rtt=507&rtt_var=56&sent=22&recv=16&lost=0&retrans=0&sent_bytes=20615&recv_bytes=3095&delivery_rate=25239361&cwnd=257&unsent_bytes=0&cid=6203a5147e5d7f55&ts=11726&x=0\"")
        .body(Body::from(compressed_body))?)
}

fn parse_query_params(
    query: &str,
) -> Result<std::collections::HashMap<String, String>, Box<dyn Error + Send + Sync>> {
    let mut params = std::collections::HashMap::new();
    // 使用 form_urlencoded 解析查询字符串
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        params.insert(key.to_string(), value.to_string());
    }
    Ok(params)
}

// 处理不允许的方法
fn handle_method_not_allowed() -> Result<Response<Body>, Box<dyn Error + Send + Sync>> {
    // 返回 405 Method Not Allowed 响应
    Ok(Response::builder()
        .status(405)
        .header("Content-Type", "text/plain")
        .body(Body::from("Method Not Allowed"))?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error  + Send + Sync>> {
    run(handler).await
}

pub async fn handler(_req: Request) -> Result<Response<Body>, Box<dyn Error  + Send + Sync>> {
            match _req.method().as_str() {
            "GET" => handle_get(_req).await,  
            _ => handle_method_not_allowed(),
        }
}