use std::collections::BTreeMap;

use chrono::Utc;
use regex::Regex;

use crate::{crypt::sha256, http_post, AcmeError};

const ACTION_ADD: &str = "add";
const ACTION_DEL: &str = "del";

mod aliyun;
mod dnspod;

pub async fn add_record(kind: &str, e: Vec<&str>, s_id: &str, s_key: &str) -> Result<String, AcmeError> {
    dispatch_record(kind, ACTION_ADD, e, s_id, s_key).await
}

pub async fn del_record(kind: &str, e: Vec<&str>, s_id: &str, s_key: &str) -> Result<String, AcmeError> {
    dispatch_record(kind, ACTION_DEL, e, s_id, s_key).await
}

async fn dispatch_record(kind: &str, tp: &str, e: Vec<&str>, s_id: &str, s_key: &str) -> Result<String, AcmeError> {
    match kind.to_lowercase().as_str() {
        "dp" | "dnspod" => _record(dnspod::DnsPod, tp, e, s_id, s_key).await,
        "ali" | "aliyun" => _record(aliyun::AliYun, tp, e, s_id, s_key).await,
        _ => return AcmeError::tip(&format!("不支持的dns api: {}。目前仅支持aliyun, dnspod", kind)),
    }
}

async fn _record<T: UtcHeaderApi3>(t: T, tp: &str, e: Vec<&str>, s_id: &str, s_key: &str) -> Result<String, AcmeError> {
    let cfg = Api3Cfg::new(tp, e, s_id, s_key);
    let ah3 = Api3Header::new(t, cfg);
    let action = ah3.action();
    let del = action.0 .0;

    let res = http_post(&ah3.url(), action.1, ah3.to_authorization(action.0)).await?;
    if res.2 == 400 || res.2 == 401 {
        return AcmeError::tip("请求API接口失败，可能签名失败，具体请参考日志");
    } else if res.2 != 200 || res.1.contains("Error") {
        return AcmeError::tip("请求API接口失败，具体请参考日志");
    }
    if del.contains("Del") {
        Ok(res.1)
    } else {
        ah3.parse_record_id(&res.1)
    }
}

trait UtcHeaderApi3 {
    fn action(&self, _type: &str, param: &Vec<String>) -> (&'static str, &'static str, String);
    fn host(&self) -> &'static str;
    fn content_type(&self) -> &'static str;
    fn alg(&self) -> &'static str;
    fn valid_headers(&self) -> Option<Vec<&'static str>> {
        None
    }

    //date,timestamp,nonce
    fn datetime(&self) -> (String, String, String) {
        let utc: chrono::DateTime<Utc> = Utc::now();
        let date = utc.date_naive().to_string();
        let timestamp = utc.timestamp().to_string();
        (date, timestamp, "".to_string())
    }

    fn canonical(&self, e: &(&'static str, &'static str, String), btm: &mut BTreeMap<&str, String>);
    fn sign(&self, s_key: &str, canonical: &str, btm: &BTreeMap<&str, String>) -> String;
    fn credential(&self, s_id: &str, _btm: &BTreeMap<&str, String>) -> String {
        s_id.to_string()
    }

    fn regx_record_id(&self) -> &'static str;

    fn parse_record_id(&self, res: &str) -> Result<String, AcmeError> {
        let re = Regex::new(self.regx_record_id())?;

        if let Some(caps) = re.captures(res) {
            Ok(caps.get(1).map_or("", |m| m.as_str()).to_string())
        } else {
            return AcmeError::tip("解析DNS记录ID失败");
        }
    }
}

struct Api3Cfg {
    action_type: String,
    s_id: String,
    s_key: String,
    param: Vec<String>,
}

impl Api3Cfg {
    fn new(action_type: &str, param: Vec<&str>, s_id: &str, s_key: &str) -> Self {
        Api3Cfg {
            action_type: action_type.to_lowercase(),
            param: param.iter().map(|s| s.to_string()).collect(),
            s_id: s_id.to_string(),
            s_key: s_key.to_string(),
        }
    }
}

struct Api3Header<T> {
    inner: T,
    cfg: Api3Cfg,
}

impl<T> Api3Header<T> {
    fn new(inner: T, cfg: Api3Cfg) -> Self {
        Api3Header { inner, cfg }
    }
    fn url(&self) -> String
    where
        T: UtcHeaderApi3,
    {
        format!("https://{}", &self.inner.host())
    }
    fn action(&self) -> ((&'static str, &'static str, String), String)
    where
        T: UtcHeaderApi3,
    {
        let action = self.inner.action(&self.cfg.action_type, &self.cfg.param);
        let hashed_payload = sha256(&action.2);
        ((action.0, action.1, hashed_payload), action.2)
    }
    fn parse_record_id(&self, res: &str) -> Result<String, AcmeError>
    where
        T: UtcHeaderApi3,
    {
        self.inner.parse_record_id(&res)
    }

    // https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature?spm=a2c4g.11186623.0.0.59bc3261dt29Ly
    fn to_authorization(&self, e: (&'static str, &'static str, String)) -> BTreeMap<&str, String>
    where
        T: UtcHeaderApi3,
    {
        let method = "POST";
        let uri = "/";

        let mut btm: BTreeMap<&str, String> = BTreeMap::new();
        btm.insert("content-type", self.inner.content_type().to_string());
        btm.insert("host", self.inner.host().to_string());

        self.inner.canonical(&e, &mut btm);

        let (mut canonical_headers, mut signed_headers) = (String::new(), String::new());
        let valid_headers = self.inner.valid_headers();
        for (i, (k, v)) in btm.iter().enumerate() {
            // let vc = if let Some(vh) = &valid_headers {
            //     if !vh.contains(k) {
            //         continue;
            //     }
            //     v.to_lowercase()
            // } else {
            //     v.to_string()
            // };
            if valid_headers.as_ref().map_or(false, |vh| !vh.contains(k)) {
                continue;
            }
            let vc = if valid_headers.is_some() {
                v.to_lowercase()
            } else {
                v.to_string()
            };

            canonical_headers.push_str(k);
            canonical_headers.push(':');
            canonical_headers.push_str(&vc);
            canonical_headers.push('\n');

            if i > 0 {
                signed_headers.push(';');
            }
            signed_headers.push_str(k);
        }

        //let canonical = format!("{}\n{}\n\n{}\n{}\n{}", method, uri, canonical_headers, &signed_headers, e.2);
        let canonical = [method, uri, "", &canonical_headers, &signed_headers, &e.2].join("\n");
        //debug!("canonical: {}", &canonical);

        let canonical = sha256(&canonical);

        let signature = self.inner.sign(&self.cfg.s_key, &canonical, &btm);

        let authorization = format!(
            "{} Credential={}, SignedHeaders={}, Signature={}",
            self.inner.alg(),
            self.inner.credential(&self.cfg.s_id, &btm),
            signed_headers,
            signature
        );

        btm.insert("authorization", authorization);
        btm
    }
}
