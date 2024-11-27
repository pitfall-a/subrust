use crate::enetity::SubInput;
use crate::server::sub_server;
use std::error::Error;
use url::form_urlencoded;
use vercel_runtime::{Body, Request, Response};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // 使用 vercel_runtime 启动应用程序
    vercel_runtime::run(|req: Request| async move {
        match req.method().as_str() {
            "GET" => handle_get(req).await,   // 处理 GET 请求
            _ => handle_method_not_allowed(), // 处理其他请求方法
        }
    })
    .await
}

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
    // 返回 200 响应
    Ok(Response::builder()
        .status(resp.code)
        .header("Content-Type", "text/plain")
        .body(Body::from(resp.body))?)
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
