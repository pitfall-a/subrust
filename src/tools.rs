use std::error::Error;

use base64::{prelude::BASE64_STANDARD, Engine};

use urlencoding::decode;

pub fn decode_base64(input: &str) -> Result<String, Box<dyn Error>> {
    if is_base64(input) {
        Ok(String::from_utf8(BASE64_STANDARD.decode(input)?)?)
    } else {
        Ok(String::from(input))
    }
}
fn is_base64(input: &str) -> bool {
    input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

pub fn decode_url_param(encoded: &str) -> String {
    decode(encoded)
        .map(|cow| cow.into_owned())
        .unwrap_or_else(|_| "Invalid encoding".to_string())
}
