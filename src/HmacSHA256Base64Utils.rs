use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use sha2::{Sha256, Sha384};

pub struct HmacSHA256Base64Utils {}

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub fn hex_hmac_sha256(secret: &str, param_string: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice((secret).as_bytes()).expect("HMAC can take key of any size");
    mac.update(param_string.as_bytes());
    let result = mac.finalize();
    let signature = result.into_bytes();
    let signature = hex::encode(signature);
    signature
}

pub fn hex_hmac_sha256_base64(secret: &str, param_string: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice((secret).as_bytes()).expect("HMAC can take key of any size");
    mac.update(param_string.as_bytes());
    let result = mac.finalize();
    STANDARD.encode(result.into_bytes())
}


pub fn hex_hmac_sha384(secret: &str, param_string: &str) -> String {
    let mut mac =
        HmacSha384::new_from_slice((secret).as_bytes()).expect("HMAC can take key of any size");
    mac.update(param_string.as_bytes());
    let result = mac.finalize();
    let signature = result.into_bytes();
    let signature = hex::encode(signature);
    signature
}

pub fn hex_hmac_sha512(secret: &str, param_string: &str) -> String {
    let mut mac =
        HmacSha512::new_from_slice((secret).as_bytes()).expect("HMAC can take key of any size");
    mac.update(param_string.as_bytes());
    let result = mac.finalize();
    let signature = result.into_bytes();
    let signature = hex::encode(signature);
    signature
}

pub fn hex_sha512(data: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub fn sign(
    time: &str,
    method: &str,
    path: &str,
    query_string: &str,
    body: &str,
    secret: &str,
) -> String {
    let mut pre_hash = String::new();
    pre_hash.push_str(time);
    pre_hash.push_str(&method.to_uppercase());
    pre_hash.push_str(path);
    if !query_string.is_empty() {
        pre_hash.push_str("?");
        pre_hash.push_str(&query_string);
    }
    if !body.is_empty() {
        pre_hash.push_str(&body);
    }
    let mut mac =
        HmacSha256::new_from_slice((secret).as_bytes()).expect("HMAC can take key of any size");
    mac.update(pre_hash.as_bytes());
    let result = mac.finalize();
    // base64::encode(result.into_bytes())
    STANDARD.encode(result.into_bytes())
}

pub fn sign_cb(
    time: &str,
    method: &str,
    path: &str,
    query_string: &str,
    body: &str,
    secret: &str,
) -> String {
    let mut pre_hash = String::new();
    pre_hash.push_str(time);
    pre_hash.push_str(&method.to_uppercase());
    pre_hash.push_str(path);
    if !query_string.is_empty() {
        pre_hash.push_str("?");
        pre_hash.push_str(&query_string);
    }
    if !body.is_empty() {
        pre_hash.push_str(&body);
    }
    let mut mac =
        HmacSha256::new_from_slice(STANDARD.decode(secret).unwrap().as_slice()).expect("HMAC can take key of any size");
    mac.update(pre_hash.as_bytes());
    let result = mac.finalize();
    STANDARD.encode(result.into_bytes())
}

pub fn map_to_query_string(mut temp: String, map: &HashMap<&str, String>) -> String {
    // if !map.is_empty() {
    for (key, value) in map {
        temp.push_str("&");
        temp.push_str(key);
        temp.push_str("=");
        temp.push_str(&value);
    }
    // remove the last "&"
    // temp.pop();
    // }
    temp
}

pub fn map_to_query_string_new(map: &HashMap<&str, String>) -> String {
    let mut temp = String::new();
    // if !map.is_empty() {
    for (key, value) in map {
        temp.push_str(key);
        temp.push_str("=");
        temp.push_str(&value);
        temp.push_str("&");
    }
    // remove the last "&"
    temp.pop();
    // }
    temp
}

//平台特殊要求，recvWindow不能放最前面，timestamp要放最前面
pub fn map_to_query_string_bian(
    map: &HashMap<&str, String>,
    recvWindow: &str,
    timestamp: &str,
) -> String {
    let mut temp = String::new();
    temp.push_str("timestamp=");
    temp.push_str(timestamp);
    temp.push_str("&recvWindow=");
    temp.push_str(recvWindow);
    temp = map_to_query_string(temp, map);
    temp
}


pub fn map_to_query_string_huobi(temp: &mut String, map: &BTreeMap<&str, String>) {
    for (key, value) in map {
        temp.push_str(key);
        temp.push_str("=");
        temp.push_str(&value);
        temp.push_str("&");
    }
    // remove the last "&"
    temp.pop();
    // }
}


