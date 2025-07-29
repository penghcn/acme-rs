use std::collections::BTreeMap;

use chrono::Utc;

use crate::crypt::hex_hmac256;

use super::{ACTION_ADD, UtcHeaderApi3};

const CONTENT_TYPE_FORM: &str = "application/x-www-form-urlencoded";

const HOST: &str = "alidns.cn-shanghai.aliyuncs.com";
const ALG: &str = "ACS3-HMAC-SHA256";

const RECORD_ADD: &str = "AddDomainRecord";
const RECORD_DEL: &str = "DeleteDomainRecord";
const VERSION: &str = "2015-01-09";
const DATE_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";
const REGX_RECORD_ID: &str = r#""RecordId":"(\d+)""#;

pub struct AliYun;
impl UtcHeaderApi3 for AliYun {
    fn alg(&self) -> &'static str {
        &ALG
    }
    fn host(&self) -> &'static str {
        &HOST
    }
    fn content_type(&self) -> &'static str {
        &CONTENT_TYPE_FORM
    }

    fn action(&self, _type: &str, e: &Vec<String>) -> (&'static str, &'static str, String) {
        let action = if _type == ACTION_ADD {
            (
                RECORD_ADD,
                VERSION,
                format!("DomainName={}&RR={}&Value={}&Type=TXT", e[0], e[1], e[2]),
            )
        } else {
            (RECORD_DEL, VERSION, format!("DomainName={}&RecordId={}", e[0], e[1]))
        };
        action
    }
    fn datetime(&self) -> (String, String, String) {
        let utc: chrono::DateTime<Utc> = Utc::now();
        let date = utc.format(DATE_FORMAT).to_string();
        let timestamp = utc.timestamp().to_string();
        (date, timestamp, utc.timestamp().to_string())
    }

    fn canonical(&self, e: &(&'static str, &'static str, String), map: &mut BTreeMap<&str, String>) {
        let utc = self.datetime();
        map.insert("x-acs-action", e.0.to_string());
        map.insert("x-acs-version", e.1.to_string());

        map.insert("x-acs-content-sha256", e.2.to_string());
        map.insert("x-acs-date", utc.0);
        map.insert("x-acs-signature-nonce", utc.2);
    }

    fn sign(&self, s_key: &str, canonical: &str, _btm: &BTreeMap<&str, String>) -> String {
        let to_sign = format!("{}\n{}", &self.alg(), canonical);
        //debug!("to_sign: {}", &to_sign);
        hex_hmac256(s_key.as_bytes(), &to_sign)
    }
    fn regx_record_id(&self) -> &'static str {
        &REGX_RECORD_ID
    }
}
