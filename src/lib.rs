mod acme;
mod crypt;
mod dnsapi;

use acme::acme_issue;
use chrono::{Duration as ChronoDuration, Local, NaiveDateTime, TimeZone};
use log::{Level, LevelFilter, Log, Record, debug, error, info};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File},
    io::Write,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::sleep_until;

const URL_LE: &str = "https://acme-v02.api.letsencrypt.org/directory"; //test https://acme-staging-v02.api.letsencrypt.org/directory
const URL_LE_INTERMEDIATE_RSA: &str = "https://letsencrypt.org/certs/2024/r10.pem"; // https://letsencrypt.org/zh-cn/certificates/
const URL_LE_INTERMEDIATE_ECC: &str = "https://letsencrypt.org/certs/2024/e5.pem";

const URL_ZERO: &str = "https://acme.zerossl.com/v2/DV90";
const URL_ZERO_EAB: &str = "https://api.zerossl.com/acme/eab-credentials-email";
//const URL_ZERO_INTERMEDIATE_RSA: &str = "https://crt.sh/?d=1282303295"; // https://help.zerossl.com/hc/en-us/articles/360060198034-Legacy-Client-Compatibility-Cross-Signed-Root-Certificates
//const URL_ZERO_INTERMEDIATE_ECC: &str = "https://crt.sh/?d=1282303296";

//注意大陆境内，该链接无法访问
const URL_GOOGLE_TRUST: &str = "https://dv.acme-v02.api.pki.goog/directory";
//const URL_GTS_INTERMEDIATE_RSA: &str = "https://i.pki.goog/r1.pem"; // https://pki.goog/repository/
//const URL_GTS_INTERMEDIATE_ECC: &str = "https://i.pki.goog/r4.pem"; // https://i.pki.goog/we1x.pem

const DIR_CA_LE: &str = "/letsencrypt/v02";
const DIR_CA_ZERO: &str = "/zerossl/v2/DV90";
const DIR_CA_GOOGLE_TRUST: &str = "/goog/v02";

const DIR_CHALLENGE: &str = "/.well-known/acme-challenge/";
const DIR_ACME: &str = "/.acme";
const DIR_BACKUP: &str = "/backup";
const PATH_CACHE_KID: &str = "/.cache.kid";
const PATH_ACCOUNT_KEY: &str = "/account.key";

const DOMAIN_KEY: &str = "domain.key";
const DOMAIN_CRT: &str = "domain.crt";
const CHAINED_CRT: &str = "chained.crt";
const DOMAIN_SSL3: [&str; 3] = [DOMAIN_KEY, DOMAIN_CRT, CHAINED_CRT];

const CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const CERT_REGEX: &str = r"(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)";
const ISSUER_REGEX: &str = r"Issuer:.*CN\s?=\s?(.*)";

const PUB_ECC_REGEX: &str = r"pub:\n\s+([0-9a-fA-F:]+(?:\n\s+[0-9a-fA-F:]+)*)";
const PUB_RSA_REGEX: &str = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)";

const CA_DEFAULT_LE: &str = "le";
const ACCOUNT_ALG_DEFAULT_EC2: &str = "EC2"; //acme接口签名等使用ecc256签名
const DOMAIN_ALG_DEFAULT_EC3: &str = "EC3"; //域名默认使用ecc384算法，可通过alg参数自定义
const ALG_HMAC_256: &str = "HS256"; //eab使用该算法签名

const CRON_DEFAULT_DAYS: i64 = 88; //每隔88天
const CRON_DEFAULT_HOUR: u32 = 0; //下一次0点执行

const CACHE_EXPIRE_DAY: u64 = 7; //7天过期
const CACHE_EXPIRE_SEC: u64 = 60 * 60 * 24 * CACHE_EXPIRE_DAY; //时间戳，7天过期
const MAX_TRY: u8 = 8; //重试最大次数
const SLEEP_DURATION_SEC_2: Duration = Duration::from_secs(2); //2s
const SLEEP_DURATION_SEC_5: Duration = Duration::from_secs(5); //5s
const LOG_LEVEL_DEAULT: LevelFilter = LevelFilter::Debug;

const CONTENT_TYPE_JSON: &str = "application/jose+json";
const USER_AGENT: HeaderValue = HeaderValue::from_static("acme.rs");
const TIMEOUT_SEC_30: Duration = Duration::from_secs(30); //30s

const FMT_LOCAL_TIME: &str = "%m/%d %H:%M:%S%.3f"; // 07/08 09:53:37.520

const TIP_MISSING_DNS: &str = "Missing parameter 'dns'";
const TIP_MISSING_DIR: &str = "Missing parameter 'dir'";
const TIP_INVALID_DNS: &str = "Wildcard domain names like *.a.com are not supported. Exactly, such as: dns=ai8.rs,www.ai8.rs";
const TIP_REGEX_FAILED: &str = "Match Regex Fialed.";

pub async fn simple_cron(cfg: &AcmeCfg) -> Result<(), AcmeError> {
    log::set_max_level(cfg.log_level);
    // quartz
    // let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(90 * 24 * 60 * 60)); //90天
    // loop {
    //     interval.tick().await;
    //     let _ = acme_issue3(&cfg).await;
    // }
    if cfg.is_cron {
        _simple_cron(cfg, CRON_DEFAULT_DAYS, CRON_DEFAULT_HOUR).await
    } else {
        _acme_issue3(&cfg).await;
        Ok(())
    }
}

pub struct AcmeLogger;
impl Log for AcmeLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= Level::Trace // 记录 Trace 及以上级别的日志
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let f = record
                .file()
                .map(|f| Path::new(f).file_name().and_then(|s| s.to_str()).unwrap_or(""))
                .unwrap_or("unknown file");
            if f == "connect.rs" {
                return;
            }
            let now_local = Local::now().format(FMT_LOCAL_TIME);
            let msg = format!(
                "{} {:5} [{}:{}] - {}",
                now_local,
                record.level(),
                f,
                record.line().unwrap_or(0),
                record.args()
            );
            println!("{}", msg);
        }
    }

    fn flush(&self) {}
}

#[derive(Debug)]
pub struct AcmeCfg {
    dns: Vec<String>,
    email: Option<String>,
    acme_root: String,   //根目录，如 /www/ai8.rs
    acme_ca_dir: String, //acme运行的ca相关，如一些缓存，如 /www/ai8.rs/.acme/letsencrypt/v02
    ssl_dir: String,     //domin.key,chained.pem等文件复制到指定的证书目录下, 默认/www/ai8.rs/.acme/ssl
    ca: AcmeCa,
    preferred_chain: Option<String>,
    domain_alg: Alg,
    log_level: LevelFilter,
    eab: Eab,
    dns_api: Option<String>,
    dns_api_sid: Option<String>,
    dns_api_key: Option<String>,
    is_cron: bool,
}

impl AcmeCfg {
    pub fn new(args: &[String]) -> Result<Self, AcmeError> {
        let map: HashMap<&str, &str> = args.iter().filter_map(|arg| arg.split_once('=')).collect();

        let is_cron = map.get("cron").is_some();
        let dns_api = map.get("da").map(|s| s.to_string());

        let dns_api_sid = map.get("da_sid").map(|s| s.to_string());
        let dns_api_key = map.get("da_key").map(|s| s.to_string());
        if dns_api.is_some() {
            if dns_api_sid.is_none() || dns_api_key.is_none() {
                return AcmeError::tip(&format!("The dns api: {}, [id or key] does not exist", dns_api.unwrap()));
            }
        }

        let dns = map.get("dns").ok_or_else(|| AcmeError::Tip(TIP_MISSING_DNS.to_string()))?;
        let dns: Vec<String> = if dns.contains("*") {
            if dns_api.is_none() {
                return AcmeError::tip(TIP_INVALID_DNS);
            }
            let dns = crypt::extract_simple_root_domain(dns);
            match dns {
                Some(d) => [format!("*.{}", &d), d].to_vec(),
                None => return AcmeError::tip(TIP_INVALID_DNS),
            }
        } else {
            dns.split(",").map(|s| s.to_string()).collect()
        };

        //let dns = dns.split(",").map(|s| s.to_string()).collect();

        let mut acme_root = map
            .get("dir")
            .ok_or_else(|| AcmeError::Tip(TIP_MISSING_DIR.to_string()))?
            .to_string();

        if !Path::new(&acme_root).is_dir() {
            if dns_api.is_none() {
                return AcmeError::tip(&format!("The directory does not exist: {}", acme_root));
            }

            acme_root = std::env::var("HOME").unwrap();
        }

        let email = map.get("email").map(|s| s.to_string());
        let ca = AcmeCa::new(map.get("ca").unwrap_or(&CA_DEFAULT_LE));
        let domain_alg = Alg::new(map.get("alg").unwrap_or(&DOMAIN_ALG_DEFAULT_EC3));

        let acme_dir = format!("{0}{1}", acme_root, DIR_ACME);
        let acme_ca_dir = format!("{0}{1}", acme_dir, ca.ca_dir());

        let ssl_dir = map.get("ssl_dir").map(|s| s.to_string()).unwrap_or(acme_dir);
        let _ = create_dir(&acme_ca_dir);

        let preferred_chain = map
            .get("preferred_chain")
            .map(|s| s.to_string())
            .or(ca.preferred_chain(domain_alg.is_ecc()));

        let log_level = match map.get("log") {
            Some(level) => match level.to_lowercase().as_str() {
                "debug" => LevelFilter::Debug,
                "trace" => LevelFilter::Trace,
                _ => LOG_LEVEL_DEAULT,
            },
            _ => LOG_LEVEL_DEAULT,
        };

        let eab_kid = map.get("eab_kid").map(|s| s.to_string());
        let eab_hmac_key = map.get("eab_key").map(|s| s.to_string());
        let eab = Eab::new(eab_kid, eab_hmac_key);

        Ok(AcmeCfg {
            dns,
            email,
            acme_root,
            acme_ca_dir,
            ssl_dir,
            ca,
            preferred_chain,
            domain_alg,
            log_level,
            eab,
            dns_api,
            dns_api_sid,
            dns_api_key,
            is_cron,
        })
    }
}

#[derive(Debug)]
pub enum AcmeError {
    ReqwestError(reqwest::Error),
    IoError(std::io::Error),
    TimeError(std::time::SystemTimeError),
    SerdeJsonError(serde_json::Error),
    RegexError(regex::Error),
    Tip(String), // 自定义错误
}

impl From<reqwest::Error> for AcmeError {
    fn from(error: reqwest::Error) -> Self {
        AcmeError::ReqwestError(error)
    }
}
impl From<std::io::Error> for AcmeError {
    fn from(error: std::io::Error) -> Self {
        AcmeError::IoError(error)
    }
}

impl From<std::time::SystemTimeError> for AcmeError {
    fn from(error: std::time::SystemTimeError) -> Self {
        AcmeError::TimeError(error)
    }
}
impl From<serde_json::Error> for AcmeError {
    fn from(error: serde_json::Error) -> Self {
        AcmeError::SerdeJsonError(error)
    }
}
impl From<regex::Error> for AcmeError {
    fn from(error: regex::Error) -> Self {
        AcmeError::RegexError(error)
    }
}

impl AcmeError {
    pub fn to_string(&self) -> String {
        match &self {
            AcmeError::ReqwestError(_e) => _e.to_string(),
            AcmeError::IoError(_e) => _e.to_string(),
            AcmeError::TimeError(_e) => _e.to_string(),
            AcmeError::SerdeJsonError(_e) => _e.to_string(),
            AcmeError::RegexError(_e) => _e.to_string(),
            AcmeError::Tip(_e) => _e.to_string(),
        }
    }

    fn tip<T>(s: &str) -> Result<T, AcmeError> {
        Err(AcmeError::Tip(s.to_string()))
    }
}

async fn _simple_cron(cfg: &AcmeCfg, days: i64, hour: u32) -> Result<(), AcmeError> {
    let mut next_execution = Local::now().naive_local(); //_next_execution(Utc::now().naive_utc(), days, hour);
    loop {
        let future = sleep_until(_tokio_instant(next_execution)?);
        tokio::pin!(future);
        future.await;

        let _ = _acme_issue3(&cfg).await;

        let next_date = next_execution + ChronoDuration::days(days);
        next_execution = next_date.date().and_hms_opt(hour, 0, 0).unwrap();
    }
}
fn _tokio_instant(next_execution: NaiveDateTime) -> Result<tokio::time::Instant, AcmeError> {
    let datetime = Local.from_local_datetime(&next_execution).unwrap();
    // 将 DateTime<Utc> 转换为 Instant
    let tt = datetime.timestamp();
    let st = SystemTime::UNIX_EPOCH + Duration::from_secs(tt as u64);
    let it = Instant::now();
    let instant = st.duration_since(SystemTime::now()).ok().map_or(it, |d| it + d);

    info!("Next execution: {:?}, {}, {:?}", datetime, tt, instant);
    Ok(tokio::time::Instant::from_std(instant))
}

// fn _next_execution(now: NaiveDateTime, days: i64, hour: u32) -> NaiveDateTime {
//     let mut execution_date = now.date().and_hms_opt(hour, 0, 0).unwrap(); // 设置为当前日期的8点
//     if execution_date < now {
//         execution_date = execution_date + ChronoDuration::days(days); // 如果已经过了8点，就设置为下一个90天
//     }
//     while execution_date.signed_duration_since(now).num_days() % days != 0 {
//         execution_date = execution_date + ChronoDuration::days(1);
//     }
//     execution_date
// }

async fn _acme_issue3(cfg: &AcmeCfg) -> () {
    // retry 2
    for i in 0..3 {
        debug!("Loop {}/3, acme issue...", i + 1);
        match acme_issue(&cfg).await {
            Err(_e) => error!("{}", _e.to_string()),
            Ok(paths) => {
                info!(
        		"Successfully.\nFor Nginx configuration:\n\tssl_certificate {1};\n\tssl_certificate_key {2};
        		\nFor Apache configuration:\n\tSSLEngine on\n\tSSLCertificateFile {0}\n\tSSLCertificateKeyFile {1}\n\tSSLCertificateChainFile {2}",
        		&paths[0], &paths[1], &paths[2]
        	);
                return;
            }
        }
        std::thread::sleep(SLEEP_DURATION_SEC_5);
    }
}

fn read_cache(_cache_path: &str) -> Option<String> {
    if let Err(e) = _cache_expire_then_rm(&_cache_path) {
        debug!("Ignore expire cache error: {:?}", e);
        return None;
    }

    match fs::read_to_string(&_cache_path) {
        Ok(s) => {
            debug!("Hit cache: {}", _cache_path);
            Some(s)
        }
        Err(_) => None,
    }
}

fn _cache_expire_then_rm(file_path: &str) -> Result<(), AcmeError> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Ok(());
    }
    let modified_time = fs::metadata(path)?.modified()?.duration_since(UNIX_EPOCH)?.as_secs();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if modified_time + CACHE_EXPIRE_SEC < now {
        debug!(
            "Cache expired. File modified > {} days, then rm: {}",
            CACHE_EXPIRE_DAY, &file_path
        );
        fs::remove_file(path)?;
    }
    Ok(())
}

fn create_dir(dir_path: &str) -> Result<(), AcmeError> {
    let _path = Path::new(&dir_path);
    if !_path.exists() {
        debug!("Created path: {:?}", _path);
        fs::create_dir_all(_path)?; // 递归创建目录
    }
    Ok(())
}

// 覆盖写入
fn write_file(file_path: &str, s: &[u8]) -> Result<(), AcmeError> {
    let _ = File::create(&file_path)
        .map_err(|_e| AcmeError::Tip(format!("Create file failed: {}. {}", file_path, _e.to_string())))?
        .write(s)
        .map_err(|_| AcmeError::Tip(format!("Write failed: {}", file_path)));
    debug!("Write to {}", file_path);
    Ok(())
}

async fn http_post(
    url: &str,
    body: String,
    headers: BTreeMap<&str, String>,
) -> Result<(reqwest::header::HeaderMap, String, u16), AcmeError> {
    http_request(&url, Some(body), headers, Method::POST).await
}

async fn http_json(
    url: &str,
    body: Option<String>,
    method: Method,
) -> Result<(reqwest::header::HeaderMap, String, u16), AcmeError> {
    let headers = vec![("content-type", CONTENT_TYPE_JSON.to_string())].into_iter().collect();
    http_request(url, body, headers, method).await
}

async fn http_request(
    url: &str,
    body: Option<String>,
    headers: BTreeMap<&str, String>,
    method: Method,
) -> Result<(reqwest::header::HeaderMap, String, u16), AcmeError> {
    //let params: HashMap<&str, &str> = [("host", h), ("type", "auto")].into_iter().collect();
    let start = Instant::now();
    debug!("==> HTTP {:?}: {}\nbody: {:?}", &method, url, &body);

    let client = reqwest::Client::new();

    let cb = match method {
        Method::GET => client.get(url),
        Method::HEAD => client.head(url),
        _ => match body {
            Some(body) => client.post(url).body(body),
            _ => client.post(url),
        },
    };

    let mut header_map = HeaderMap::new();
    header_map.append("User-Agent", USER_AGENT);
    for (k, v) in headers {
        header_map.append(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_bytes(v.as_bytes()).unwrap(),
        );
    }
    debug!("==> Request Headers: {:?}", &header_map);
    let request_builder = cb.headers(header_map).timeout(TIMEOUT_SEC_30);

    let response = request_builder.send().await.map_err(AcmeError::from)?;

    let (c, h) = (response.status().as_u16(), response.headers().clone());
    debug!(
        "<== Response: {}, duration: {:.1}s. Header: {:?}",
        c,
        start.elapsed().as_secs_f32(),
        response.headers()
    );

    let res = response.text().await?;
    debug!("<== Response: {}", res);
    Ok((h, res, c))
}

trait CA {
    fn ca_dir(&self) -> &'static str;
    fn directory_url(&self) -> &'static str;
}
struct LetsEncrypt;
struct ZeroSSL;
struct GoogleTrustServices;

impl CA for LetsEncrypt {
    fn ca_dir(&self) -> &'static str {
        DIR_CA_LE
    }
    fn directory_url(&self) -> &'static str {
        URL_LE
    }
}

impl CA for ZeroSSL {
    fn ca_dir(&self) -> &'static str {
        DIR_CA_ZERO
    }
    fn directory_url(&self) -> &'static str {
        URL_ZERO
    }
}

impl CA for GoogleTrustServices {
    fn ca_dir(&self) -> &'static str {
        DIR_CA_GOOGLE_TRUST
    }
    fn directory_url(&self) -> &'static str {
        URL_GOOGLE_TRUST
    }
}

enum AcmeCa {
    LetsEncrypt(Box<dyn CA>),
    ZeroSSL(Box<dyn CA>),
    GoogleTrustServices(Box<dyn CA>),
}

// 只是简单实现 Debug trait，并不会真实打印。编译器不会再报错
impl std::fmt::Debug for AcmeCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeCa::LetsEncrypt(_) => write!(f, "AcmeCa::LetsEncrypt"),
            AcmeCa::ZeroSSL(_) => write!(f, "AcmeCa::ZeroSSL"),
            AcmeCa::GoogleTrustServices(_) => write!(f, "AcmeCa::GoogleTrustServices"),
        }
    }
}

impl AcmeCa {
    fn new(ca_type: &str) -> Self {
        match ca_type {
            CA_DEFAULT_LE => AcmeCa::LetsEncrypt(Box::new(LetsEncrypt)),
            "z" | "zero" => AcmeCa::ZeroSSL(Box::new(ZeroSSL)),
            "g" | "gts" => AcmeCa::GoogleTrustServices(Box::new(GoogleTrustServices)),
            _ => AcmeCa::LetsEncrypt(Box::new(LetsEncrypt)),
        }
    }
    fn ca_dir(&self) -> String {
        self.ca().ca_dir().to_string()
    }
    fn directory_url(&self) -> String {
        self.ca().directory_url().to_string()
    }
    fn eab_url(&self) -> Option<String> {
        match self {
            AcmeCa::ZeroSSL(_) => Some(URL_ZERO_EAB.to_string()),
            _ => None,
        }
    }
    fn preferred_chain(&self, is_ecc: bool) -> Option<String> {
        match self {
            AcmeCa::LetsEncrypt(_) => Some(format!("ISRG ROOT X{}", if is_ecc { "2" } else { "1" })),
            _ => None,
        }
    }
    fn intermediate_url(&self, is_ecc: bool) -> Option<String> {
        match self {
            AcmeCa::LetsEncrypt(_) => Some(
                if is_ecc {
                    URL_LE_INTERMEDIATE_ECC
                } else {
                    URL_LE_INTERMEDIATE_RSA
                }
                .to_string(),
            ),
            _ => None,
        }
    }
    fn ca(&self) -> &dyn CA {
        match self {
            AcmeCa::LetsEncrypt(ca) => ca.as_ref(),
            AcmeCa::ZeroSSL(ca) => ca.as_ref(),
            AcmeCa::GoogleTrustServices(ca) => ca.as_ref(),
        }
    }
}

#[derive(Debug)]
enum Alg {
    RSA2048,
    RSA4096,
    ECC256,
    ECC384,
}
impl Alg {
    fn new(alg: &str) -> Self {
        match alg.to_uppercase().as_str() {
            DOMAIN_ALG_DEFAULT_EC3 | "ECC3" => Alg::ECC384,
            "EC2" | "ECC2" => Alg::ECC256,
            "RSA4" => Alg::RSA4096,
            "RSA2" => Alg::RSA2048,
            _ => Alg::ECC384, //default
        }
    }

    fn is_ecc(&self) -> bool {
        matches!(self, Alg::ECC256 | Alg::ECC384)
    }
}

#[derive(Deserialize, Debug)]
struct Eab {
    success: bool,
    error: Option<EabError>,
    eab_kid: Option<String>,
    eab_hmac_key: Option<String>,
}
impl Eab {
    fn new(eab_kid: Option<String>, eab_hmac_key: Option<String>) -> Self {
        Eab {
            success: eab_kid.is_some() & eab_hmac_key.is_some(),
            eab_kid,
            eab_hmac_key,
            error: None,
        }
    }
    fn _clone(eab: &Eab) -> Option<Self> {
        Some(Self::new(eab.eab_kid.clone(), eab.eab_hmac_key.clone()))
    }

    fn _kid(&self) -> String {
        if self.success {
            format!(".{}", self.eab_kid.clone().unwrap())
        } else {
            "".to_string()
        }
    }
}

#[derive(Deserialize, Debug)]
struct EabError {
    code: u32,
    #[serde(rename(deserialize = "type"))]
    _type: Option<String>,
    info: Option<String>,
}

#[derive(Debug)]
enum Method {
    POST,
    GET,
    HEAD,
}

// #[tokio::test]
// async fn t2() -> Result<(), AcmeError> {
//     log::set_boxed_logger(Box::new(AcmeLogger)).unwrap();
//     log::set_max_level(LevelFilter::Debug);

//     let domain = vec![
//         "passet.com.cn",
//         "*.passet.com.cn",
//         "passet.com.cn,*.passet.com.cn",
//         "*.passet.com.cn,a.passet.com.cn",
//         "*.p.cn",
//         "*.p.cn,a.p.cn",
//         "a.p.cn,*.p.cn",
//         "p.io",
//     ];
//     for d in &domain {
//         println!("{}  -> {:?}", d, crypt::extract_simple_root_domain(d));
//     }

//     Ok(())
// }
