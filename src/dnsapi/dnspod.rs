use std::collections::BTreeMap;

use crate::crypt::{hex_hmac256, hmac256};

use super::{ACTION_ADD, UtcHeaderApi3};

const CONTENT_TYPE_JSON: &str = "application/json";

const HOST: &str = "dnspod.tencentcloudapi.com";
const ALG: &str = "TC3-HMAC-SHA256";

const RECORD_ADD: &str = "CreateRecord";
const RECORD_DEL: &str = "DeleteRecord";
const VERSION: &str = "2021-03-23";

const SERVICE: &str = "dnspod";
const TC3_REQUEST: &str = "tc3_request";
const VALID_HEADERS: [&str; 3] = ["content-type", "host", "x-tc-action"];
const REGX_RECORD_ID: &str = r#""RecordId":\s*(\d+)"#;

pub struct DnsPod;

impl UtcHeaderApi3 for DnsPod {
    fn alg(&self) -> &'static str {
        &ALG
    }
    fn content_type(&self) -> &'static str {
        CONTENT_TYPE_JSON
    }
    fn host(&self) -> &'static str {
        &HOST
    }
    fn valid_headers(&self) -> Option<Vec<&'static str>> {
        Some(VALID_HEADERS.to_vec())
    }

    fn action(&self, _type: &str, e: &Vec<String>) -> (&'static str, &'static str, String) {
        let action = if _type == ACTION_ADD {
            (
                RECORD_ADD,
                VERSION,
                format!(
                    "{{\"Domain\":\"{}\",\"SubDomain\":\"{}\",\"Value\":\"{}\",\"RecordType\":\"TXT\",\"RecordLine\":\"默认\"}}",
                    e[0], e[1], e[2]
                ),
            )
        } else {
            (
                RECORD_DEL,
                VERSION,
                format!("{{\"Domain\":\"{}\",\"RecordId\":{}}}", e[0], e[1]),
            )
        };
        action
    }
    fn canonical(&self, e: &(&'static str, &'static str, String), map: &mut BTreeMap<&str, String>) {
        let utc = self.datetime();

        map.insert("x-tc-action", e.0.to_string());
        map.insert("x-tc-version", e.1.to_string());
        map.insert("x-tc-date", utc.0);
        map.insert("x-tc-timestamp", utc.1);
    }
    fn sign(&self, s_key: &str, canonical: &str, btm: &BTreeMap<&str, String>) -> String {
        let date = btm.get("x-tc-date").unwrap();
        let timestamp = btm.get("x-tc-timestamp").unwrap();

        let credential_scope = format!("{}/{}/{}", date, &SERVICE, &TC3_REQUEST);
        let to_sign = format!("{}\n{}\n{}\n{}", self.alg(), timestamp, credential_scope, canonical);

        //debug!("to_sign: {}", &to_sign);

        let signature = hmac256(format!("TC3{}", s_key).as_bytes(), date);
        let signature = hmac256(&signature, &SERVICE);
        let signature = hmac256(&signature, &TC3_REQUEST);
        hex_hmac256(&signature, &to_sign)
    }
    fn credential(&self, s_id: &str, btm: &BTreeMap<&str, String>) -> String {
        let date = btm.get("x-tc-date").unwrap();
        format!("{}/{}/{}/{}", s_id, date, &SERVICE, &TC3_REQUEST)
    }
    fn regx_record_id(&self) -> &'static str {
        &REGX_RECORD_ID
    }
}
