use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chrono::Local;
use hmac::{Hmac, Mac};
use log::{debug, info, trace, warn, Level, LevelFilter, Log, Record};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const URL_LE: &str = "https://acme-v02.api.letsencrypt.org/directory";
const URL_LE_INTERMEDIATE_RSA: &str = "https://letsencrypt.org/certs/2024/r11.pem"; // https://letsencrypt.org/zh-cn/certificates/
const URL_LE_INTERMEDIATE_ECC: &str = "https://letsencrypt.org/certs/2024/e6.pem";

const URL_ZERO: &str = "https://acme.zerossl.com/v2/DV90";
const URL_ZERO_EAB: &str = "https://api.zerossl.com/acme/eab-credentials-email";
const URL_ZERO_INTERMEDIATE_RSA: &str = "https://crt.sh/?d=1282303295"; // https://help.zerossl.com/hc/en-us/articles/360060198034-Legacy-Client-Compatibility-Cross-Signed-Root-Certificates
const URL_ZERO_INTERMEDIATE_ECC: &str = "https://crt.sh/?d=1282303296";

const URL_GOOGLE_TRUST: &str = "https://dv.acme-v02.api.pki.goog/directory"; //注意大陆境内，该链接无法访问
const URL_GTS_INTERMEDIATE_RSA: &str = "https://pki.goog/roots.pem"; // https://pki.goog/faq/#faq-27
const URL_GTS_INTERMEDIATE_ECC: &str = "https://pki.goog/roots.pem"; // 使用的是rsa，无独立的ecc证书链

const DIR_CA_LE: &str = "/letsencrypt/v02";
const DIR_CA_ZERO: &str = "/zerossl/v2/DV90";
const DIR_CA_GOOGLE_TRUST: &str = "/goog/v02";

const DIR_CHALLENGES: &str = "/challenges/";
const DIR_ACME: &str = "/.acme";
const DIR_BACKUP: &str = "/.backup";
const PATH_CACHE_KID: &str = "/.cache.kid";
const PATH_ACCOUNT_KEY: &str = "/account.key";

const DOMAIN_KEY: &str = "domain.key";
const DOMAIN_CRT: &str = "sign.crt";
const CHAINED_CRT: &str = "chained.crt";

const CA_DEFAULT_LE: &str = "le";
const ACCOUNT_ALG_DEFAULT_EC2: &str = "EC2"; //acme接口签名等使用ecc256签名
const DOMAIN_ALG_DEFAULT_EC3: &str = "EC3"; //域名默认使用ecc384算法，可通过alg参数自定义
const ALG_HMAC_256: &str = "HS256"; //eab使用该算法签名

const CACHE_EXPIRE_DAY: u64 = 7; //7天过期
const CACHE_EXPIRE_SEC: u64 = 60 * 60 * 24 * CACHE_EXPIRE_DAY; //时间戳，7天过期
const MAX_TRY: u8 = 8; //重试最大次数
const SLEEP_DURATION_SEC_2: Duration = Duration::from_secs(2); //2s
const SLEEP_DURATION_SEC_5: Duration = Duration::from_secs(5); //5s
const LOG_LEVEL_DEAULT: LevelFilter = LevelFilter::Debug;

const FMT_LOCAL_TIME: &str = "%m/%d %H:%M:%S%.3f"; // 07/08 09:53:37.520

const CONTENT_TYPE_JSON: &str = "application/jose+json";
const USER_AGENT: &str = "acme.rs";
const TIMEOUT_SEC_10: Duration = Duration::from_secs(10); //10s

const HEADER_REPLAY_NONCE: &str = "replay-nonce";
const HEADER_LOCATION: &str = "location";
const TYPE_HTTP: &str = "http-01";
const STATUS_OK: &str = "valid"; //valid. pending, ready, processing. invalid

const TIP_MISSING_DNS: &str = "Missing parameter 'dns'";
const TIP_MISSING_DIR: &str = "Missing parameter 'dir'";
const TIP_INVALID_DNS: &str = "Wildcard domain names like *.a.com are not supported. Exactly, such as: dns=ai8.rs,www.ai8.rs";
const TIP_REQUIRED_EMAIL: &str = "Required email, add param like: email=a@a.org";
const TIP_DOWN_CRT_FAILED: &str = "Download certificate failed, exiting.";
const TIP_MAX_TRY: &str = "Maximum attempts reached, exiting.";
const TIP_EAB_FAILED: &str = "Get Eab Fialed.";
const TIP_TYPE_HTTP_FAILED: &str = "Get challenges http-01 Fialed.";

// acme规范参考 https://datatracker.ietf.org/doc/html/rfc8555#section-7.2
#[tokio::main]
async fn main() {
    //set log
    log::set_boxed_logger(Box::new(AcmeLogger)).unwrap();
    log::set_max_level(LevelFilter::Info);
    // cargo test --test acme -- _acme --exact --show-output  dns=ai8.rs,www.ai8.rs dir=/www/ai8.rs email=a@a.org ca=z
    // cargo run --  dns=ai8.rs,www.ai8.rs dir=/www/ai8.rs ca=z email=a@a.rs alg=rsa4
    let args: Vec<String> = std::env::args().skip(1).collect(); // 获取所有的命令行参数，跳过第一个参数（程序路径）
    info!("Get args: {:?}", &args);

    let cfg = match AcmeCfg::new(args) {
        Err(_e) => {
            info!("{:?}", _e);
            return; //中断
        }
        Ok(cfg) => cfg,
    };

    //set log
    log::set_max_level(cfg.log_level);

    // ssl_certificate .../le_ssl_chained.pem;
    // ssl_certificate_key .../le_ssl_domain.key;
    match acme_run(cfg).await {
        Err(_e) => warn!("{}", _e.to_string()),
        Ok(paths) => {
            info!(
                "Successfully.\nFor Nginx configuration:\n\tssl_certificate {1}\n\tssl_certificate_key {2}
				\nFor Apache configuration:\n\tSSLEngine on\n\tSSLCertificateFile {0}\n\tSSLCertificateKeyFile {1}\n\tSSLCertificateChainFile {2}",
                paths.0, paths.1, paths.2
            );
        }
    }
}

async fn acme_run(cfg: AcmeCfg) -> Result<(String, String, String), AcmeError> {
    // 0 初始化参数，获取或者默认值
    info!("Step 1 Init Params: {:?}", cfg);

    // 1 init获取接口  /directory
    let dir = _directory(cfg.ca.directory_url()).await?;
    info!("Step 2 GET Directory. {:?}", dir);
    let external_account_required = dir.meta.external_account_required.unwrap_or(false);

    // 1.1 是否需要扩展账户信息eab，目前就是zerossl,gts
    if external_account_required & cfg.email.is_none() {
        return AcmeError::tip(TIP_REQUIRED_EMAIL);
    }

    // 3.1 先获取或生成 account.key, 通过参数指定(参考enum Alg)， 目前支持 rsa2048,rsa4096,prime256v1,prime384v1,prime512v1
    let account_key_path = format!("{0}{1}", cfg.acme_ca_dir, PATH_ACCOUNT_KEY);
    let acccount_alg = Alg::new(ACCOUNT_ALG_DEFAULT_EC2); //cfg.alg;

    if _read_cache(&account_key_path).is_none() {
        let _ = _gen_key_by_cmd_openssl(&account_key_path, &acccount_alg);
        let kid_cache_path = format!("{0}{1}", cfg.acme_ca_dir, PATH_CACHE_KID);
        let kid_cache_path = Path::new(&kid_cache_path);
        if kid_cache_path.exists() {
            fs::remove_file(kid_cache_path)?; //同时删除cache.kid
        }
        info!("Step 3.1 Gen account key by {:?}: {}", &acccount_alg, &account_key_path);
    }

    let jwk = _print_key_by_cmd_openssl(&account_key_path, acccount_alg.is_ecc())?;
    let alg = jwk.alg();
    let thumbprint = _base64_sha256(&jwk.to_string());
    debug!("\njwk: {:?}, thumbprint:{}", jwk, thumbprint);

    // 3.2 获取nonce接口  /acme/new-nonce
    info!("Step 3.2 POST new nonce.");
    let nonce = _new_nonce(&dir.new_nonce).await?;

    // 3.3 注册账号接口 /acme/new-acct
    //let email = if external_account_required { cfg.email } else { None };
    //let email = cfg.email.filter(|_| external_account_required);
    let (nonce, kid) = _new_acct(dir.new_account, nonce, &cfg, &account_key_path, &alg, jwk).await?;
    info!("Step 3.3 GET account. {}", kid);

    // 4 下单 -> 验证每个域名 -> 验证每个域名
    // 4.1 下单 /acme/new-order
    let (nonce, order_res) = _new_order(&dir.new_order, nonce, &account_key_path, &alg, &kid, &cfg.dns).await?;
    info!("Step 4.1 GET order. {}", nonce);

    // 4.2 验证每个域名
    info!("Step 4.2 Authorization each domain. {:?}", &cfg.dns);
    let mut mut_nonce = nonce;
    for _authz_url in order_res.authorizations.unwrap() {
        let (nonce, auth_order_res) = _auth_domain(&_authz_url, mut_nonce, &account_key_path, &alg, &kid).await?;
        mut_nonce = nonce;

        let is_ok = auth_order_res.is_ok();
        let (domain, challenges) = (auth_order_res.identifier.unwrap().value, auth_order_res.challenges.unwrap());
        if is_ok {
            info!("Verifyed {0}.", domain);
            continue;
        }

        info!("Verifying {0}...", domain);
        let chall = challenges.into_iter().filter(|c| c._type == TYPE_HTTP).next();
        let chall = match chall {
            Some(chall) => chall,
            None => return AcmeError::tip(TIP_TYPE_HTTP_FAILED),
        };

        let mut attempts: u8 = 0; //轮询auth
        loop {
            let (nonce, auth_order_res) = _auth_domain(&_authz_url, mut_nonce, &account_key_path, &alg, &kid).await?;
            mut_nonce = nonce;
            if auth_order_res.is_ok() || auth_order_res.status == "pending" {
                break;
            }
            attempts += 1;

            if attempts == MAX_TRY {
                return AcmeError::tip(TIP_MAX_TRY);
            }
            let _ = std::thread::sleep(SLEEP_DURATION_SEC_2);
            debug!("Loop {}/{}, auth domain", attempts, MAX_TRY);
        }

        let well_known_path = _write_to_challenges(chall.token, &domain, &cfg.acme_root, &thumbprint).await?;

        let mut attempts: u8 = 0; //轮询challenges
        loop {
            let (_nonce, _ok) = _chall_domain(&chall.url, mut_nonce, &account_key_path, &alg, &kid).await?;
            mut_nonce = _nonce;
            if _ok {
                println!("Successful.{}", &chall.url);
                break;
            }
            attempts += 1;

            if attempts == MAX_TRY {
                return AcmeError::tip(TIP_MAX_TRY);
            }
            let _ = std::thread::sleep(SLEEP_DURATION_SEC_2);
            debug!("Loop {}/{}, challenges domain", attempts, MAX_TRY);
        }
        let _ = fs::remove_file(&well_known_path).map_err(|_| AcmeError::Tip(format!("Remove failed: {}", well_known_path)));
    }

    // 4.3 finalize csr
    let (csr, domain_key_path) = _gen_csr_by_cmd_openssl(&cfg.acme_dir, &cfg.domain_alg, &cfg.dns)?;

    info!("Step 4.3 Finalize domain with csr.");
    let fin_url = &order_res.finalize.unwrap();

    let (nonce, os_url, or) = _finalize_csr(fin_url, mut_nonce, &account_key_path, &alg, &kid, csr.clone()).await?;
    mut_nonce = nonce;

    let cert_url: Option<String>;
    if or.is_ok() {
        cert_url = or.certificate;
    } else {
        //轮询
        let mut attempts: u8 = 0;
        loop {
            let (nonce, or) = _order_status(&os_url, mut_nonce, &account_key_path, &alg, &kid).await?;
            mut_nonce = nonce;
            if or.is_ok() {
                cert_url = or.certificate;
                break;
            }
            attempts += 1;

            if attempts == MAX_TRY {
                return AcmeError::tip(TIP_MAX_TRY);
            }
            let _ = std::thread::sleep(SLEEP_DURATION_SEC_5);
            debug!("Loop {}/{}, order status", attempts, MAX_TRY);
        }
    }

    // 4.4 down certificate
    let cert_url = match cert_url {
        Some(url) => url,
        None => return AcmeError::tip(TIP_DOWN_CRT_FAILED),
    };
    info!("Step 4.4 Download certificate file. Named {}", DOMAIN_CRT);
    let sign_crt = _down_certificate(&cert_url, mut_nonce, &account_key_path, &alg, &kid).await?;

    info!("Step 4.5 Download ca intermediate file. Named intermediate.pem");
    let _intermediate_pem = match cfg.ca {
        AcmeCa::LetsEncrypt(ca) | AcmeCa::ZeroSSL(ca) => {
            let _intermediate_crt_url = ca.intermediate_crt_url(acccount_alg.is_ecc());
            _http_json(&_intermediate_crt_url, None, Method::GET).await?.1
        }
        _ => "".to_string(),
    };

    // 5.1、最后，合并sign.crt和intermediate.pem的内容成 chained.pem
    let sign_crt_path = format!("{}/{}", cfg.acme_dir, DOMAIN_CRT);
    let chained_pem_path = format!("{}/{}", cfg.acme_dir, CHAINED_CRT);
    info!("Step 5.1 Combine {} and intermediate.pem", DOMAIN_CRT);

    let _ = _write_to_file(&sign_crt_path, &sign_crt)?;
    let _ = _write_to_file(&chained_pem_path, &format!("{0}\n{1}", sign_crt, _intermediate_pem))?;

    // 5.2、复制小文件到备份目录
    let bk_no = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let bk_dir = format!("{0}{1}", cfg.acme_ca_dir, DIR_BACKUP);

    info!("Step 5.2 Backup to: {}", &bk_dir);
    let bk_dir_path = Path::new(&bk_dir);
    if !bk_dir_path.exists() {
        debug!("Created path: {:?}", bk_dir_path);
        fs::create_dir_all(bk_dir_path)?; // 递归创建目录
    }

    let _ = fs::copy(&sign_crt_path, format!("{}/{}.{}", bk_dir, bk_no, DOMAIN_CRT))?;
    let _ = fs::copy(&chained_pem_path, format!("{}/{}.{}", bk_dir, bk_no, CHAINED_CRT))?;
    let _ = fs::copy(&domain_key_path, format!("{}/{}.{}", bk_dir, bk_no, DOMAIN_KEY))?;

    //5.3 若需要，复制到指定的证书目录下，文件名不变
    if let Some(ssl_dir) = cfg.ssl_dir {
        info!("Step 5.3 Copy to: {}", &ssl_dir);
        if !Path::new(&ssl_dir).exists() {
            return AcmeError::tip(&format!("The directory does not exist: {}", &ssl_dir));
        }
        let _ = fs::copy(&sign_crt_path, format!("{}/{}", ssl_dir, DOMAIN_CRT))?;
        let _ = fs::copy(&chained_pem_path, format!("{}/{}", ssl_dir, CHAINED_CRT))?;
        let _ = fs::copy(&domain_key_path, format!("{}/{}", ssl_dir, DOMAIN_KEY))?;
    }

    let result = (sign_crt_path, chained_pem_path, domain_key_path);

    Ok(result)
}

trait CA {
    fn ca_dir(&self) -> &'static str;
    fn directory_url(&self) -> &'static str;
    fn intermediate_crt_url(&self, is_ecc: bool) -> &'static str;
}
struct LetsEncrypt;
struct ZeroSSL;
struct GoogleTrust;

impl CA for LetsEncrypt {
    fn ca_dir(&self) -> &'static str {
        DIR_CA_LE
    }
    fn directory_url(&self) -> &'static str {
        URL_LE
    }
    fn intermediate_crt_url(&self, is_ecc: bool) -> &'static str {
        if is_ecc {
            URL_LE_INTERMEDIATE_ECC
        } else {
            URL_LE_INTERMEDIATE_RSA
        }
    }
}

impl CA for ZeroSSL {
    fn ca_dir(&self) -> &'static str {
        DIR_CA_ZERO
    }
    fn directory_url(&self) -> &'static str {
        URL_ZERO
    }
    fn intermediate_crt_url(&self, is_ecc: bool) -> &'static str {
        if is_ecc {
            URL_ZERO_INTERMEDIATE_ECC
        } else {
            URL_ZERO_INTERMEDIATE_RSA
        }
    }
}

impl CA for GoogleTrust {
    fn ca_dir(&self) -> &'static str {
        DIR_CA_GOOGLE_TRUST
    }
    fn directory_url(&self) -> &'static str {
        URL_GOOGLE_TRUST
    }
    fn intermediate_crt_url(&self, is_ecc: bool) -> &'static str {
        if is_ecc {
            URL_GTS_INTERMEDIATE_ECC
        } else {
            URL_GTS_INTERMEDIATE_RSA
        }
    }
}

enum AcmeCa {
    LetsEncrypt(Box<dyn CA>),
    ZeroSSL(Box<dyn CA>),
    GoogleTrust(Box<dyn CA>),
}

// 只是简单实现 Debug trait，并不会真实打印。编译器不会再报错
impl std::fmt::Debug for AcmeCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeCa::LetsEncrypt(_) => write!(f, "AcmeCa::LetsEncrypt"),
            AcmeCa::ZeroSSL(_) => write!(f, "AcmeCa::ZeroSSL"),
            AcmeCa::GoogleTrust(_) => write!(f, "AcmeCa::GoogleTrust"),
        }
    }
}

impl AcmeCa {
    fn new(ca_type: &str) -> Self {
        match ca_type {
            CA_DEFAULT_LE => AcmeCa::LetsEncrypt(Box::new(LetsEncrypt)),
            "z" | "zero" => AcmeCa::ZeroSSL(Box::new(ZeroSSL)),
            "g" | "google" => AcmeCa::GoogleTrust(Box::new(GoogleTrust)),
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
    // fn intermediate_crt_url(&self, is_ecc: bool) -> String {
    //     self.ca().intermediate_crt_url(is_ecc).to_string()
    // }
    fn ca(&self) -> &dyn CA {
        match self {
            AcmeCa::LetsEncrypt(ca) => ca.as_ref(),
            AcmeCa::ZeroSSL(ca) => ca.as_ref(),
            AcmeCa::GoogleTrust(ca) => ca.as_ref(),
        }
    }
}

struct AcmeLogger;
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
struct AcmeCfg {
    dns: Vec<String>,
    email: Option<String>,
    acme_root: String,   //根目录，如 /www/ai8.rs
    acme_dir: String,    //acme运行的目录，如 /www/ai8.rs/.acme
    acme_ca_dir: String, //acme运行的ca相关，如一些缓存，如 /www/ai8.rs/.acme/letsencrypt/v02
    ca: AcmeCa,
    domain_alg: Alg,
    log_level: LevelFilter,
    eab: Eab,
    ssl_dir: Option<String>, //domin.key,chained.pem等文件复制到指定的证书目录下
}

impl AcmeCfg {
    fn new(args: Vec<String>) -> Result<Self, AcmeError> {
        let mut map: HashMap<&str, &str> = HashMap::new();
        for arg in args.iter() {
            //let (k, v) = arg.split_once('=').ok_or_else(|| AcmeError::Tip("参数格式错误".to_string()))?;
            //map.insert(k, v);
            if let Some((k, v)) = arg.split_once('=') {
                map.insert(k, v);
            }
        }

        let dns = map.get("dns").ok_or_else(|| AcmeError::Tip(TIP_MISSING_DNS.to_string()))?;

        if dns.contains("*") {
            return AcmeError::tip(TIP_INVALID_DNS);
        }
        let dns = dns.split(",").map(|s| s.to_string()).collect();

        let acme_root = map
            .get("dir")
            .ok_or_else(|| AcmeError::Tip(TIP_MISSING_DIR.to_string()))?
            .to_string();

        if !Path::new(&acme_root).is_dir() {
            return AcmeError::tip(&format!("The directory does not exist: {}", acme_root));
        }

        let email = map.get("email").map(|s| s.to_string());
        let ca = AcmeCa::new(map.get("ca").unwrap_or(&CA_DEFAULT_LE));
        let domain_alg = Alg::new(map.get("alg").unwrap_or(&DOMAIN_ALG_DEFAULT_EC3));

        let acme_dir = format!("{0}{1}", acme_root, DIR_ACME);
        let acme_ca_dir = format!("{0}{1}", acme_dir, ca.ca_dir());
        let _path = Path::new(&acme_ca_dir);
        if !_path.exists() {
            println!("Create path: {:?}", _path);
            fs::create_dir_all(_path)?; // 递归创建目录
        }

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
        let ssl_dir = map.get("ssl_dir").map(|s| s.to_string());

        Ok(AcmeCfg {
            dns,
            email,
            acme_root,
            acme_dir,
            acme_ca_dir,
            ca,
            domain_alg,
            log_level,
            eab,
            ssl_dir,
        })
    }
}

#[derive(Debug)]
enum AcmeError {
    ReqwestError(reqwest::Error),
    IoError(std::io::Error),
    TimeError(std::time::SystemTimeError),
    SerdeJsonError(serde_json::Error),
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

impl AcmeError {
    fn to_string(&self) -> String {
        match &self {
            AcmeError::ReqwestError(_e) => _e.to_string(),
            AcmeError::IoError(_e) => _e.to_string(),
            AcmeError::TimeError(_e) => _e.to_string(),
            AcmeError::SerdeJsonError(_e) => _e.to_string(),
            AcmeError::Tip(_e) => _e.to_string(),
        }
    }

    fn tip<T>(s: &str) -> Result<T, AcmeError> {
        Err(AcmeError::Tip(s.to_string()))
    }
}

#[derive(Debug)]
enum Method {
    POST,
    GET,
    HEAD,
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
#[serde(rename_all(deserialize = "camelCase"))]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    meta: DirectoryMeta,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all(deserialize = "camelCase"))]
struct DirectoryMeta {
    //terms_of_service: String,
    //website: String,
    //caa_identities: Vec<String>,
    external_account_required: Option<bool>,
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
}

#[derive(Deserialize, Debug)]
struct EabError {
    code: u32,
    #[serde(rename(deserialize = "type"))]
    _type: Option<String>,
    info: Option<String>,
}

#[derive(Serialize, Debug)]
struct JwkEcc {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl JwkEcc {
    fn new(crv: String, x: String, y: String) -> Self {
        JwkEcc {
            kty: String::from("EC"),
            crv,
            x,
            y,
        }
    }
}

#[derive(Serialize, Debug)]
struct JwkRsa {
    e: String,
    kty: String,
    n: String,
}

impl JwkRsa {
    fn new(e: String, n: String) -> Self {
        JwkRsa {
            kty: String::from("RSA"),
            e,
            n,
        }
    }
}

// 参考serde用法详解 https://blog.wangjunfeng.com/post/2024/rust-serde/#serderename--name-1
#[derive(Serialize, Debug)]
#[serde(untagged)]
enum Jwk {
    _Ecc(JwkEcc),
    _Rsa(JwkRsa),
}
impl Jwk {
    fn call(out: &str, is_ecc: bool) -> Result<Self, AcmeError> {
        //let is_ecc= out.starts_with("Private-Key:");
        if is_ecc {
            let pub_ = _regx(&out, r"pub:\n\s+([0-9a-fA-F:]+(?:\n\s+[0-9a-fA-F:]+)*)", true);
            let crv = _regx(&out, r"NIST CURVE: (.*)", false);

            let offset = pub_.len() / 2 + 1;
            let (x, y) = (_base64_hex(&pub_[2..offset]), _base64_hex(&pub_[offset..]));
            Ok(Self::_Ecc(JwkEcc::new(crv, x, y)))
        } else {
            let pub_ = _regx(&out, r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)", true);
            let e = _regx(&out, r"0x([A-Fa-f0-9]+)", false);
            let e = if e.len() % 2 == 0 { e } else { format!("0{}", e) };
            println!("{}: {}", &e, &pub_);

            let (e64, n) = (_base64_hex(&e), _base64_hex(&pub_));

            Ok(Self::_Rsa(JwkRsa::new(e64, n)))
        }
    }

    fn alg(&self) -> String {
        match self {
            Jwk::_Ecc(_ecc) => format!("ES{}", &_ecc.crv[2..]), //e.g. ES384
            _ => "RS256".to_string(),
        }
    }
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

#[derive(Serialize, Debug)]
struct Protected<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    url: &'a str,
    alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}
impl<'a> Protected<'a> {
    pub fn from(url: &'a str, nonce: String, alg: &'a str, jwk: Jwk) -> Self {
        Protected {
            url,
            nonce: Some(nonce),
            alg,
            jwk: Some(jwk),
            kid: None,
        }
    }
    pub fn from_kid(url: &'a str, nonce: String, alg: &'a str, kid: &'a str) -> Self {
        Protected {
            url,
            nonce: Some(nonce),
            alg,
            jwk: None,
            kid: Some(kid),
        }
    }
    pub fn from_eab(url: &'a str, alg: &'a str, kid: &'a str) -> Self {
        Protected {
            url,
            nonce: None,
            alg,
            jwk: None,
            kid: Some(kid),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Identifier {
    #[serde(rename = "type")]
    _type: String,
    value: String,
}
impl Identifier {
    pub fn new(value: String) -> Self {
        Identifier {
            _type: "dns".to_string(),
            value,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all(serialize = "camelCase"))]
struct Payload {
    #[serde(skip_serializing_if = "Option::is_none")]
    contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_account_binding: Option<SigBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifiers: Option<Vec<Identifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    csr: Option<String>,
}
impl Payload {
    fn _new_acct() -> Option<Self> {
        Some(Payload {
            identifiers: None,
            external_account_binding: None,
            contact: None,
            terms_of_service_agreed: Some(true),
            csr: None,
        })
    }
    fn _new_acct_with_eab(email: &str, external_account_binding: Option<SigBody>) -> Option<Self> {
        Some(Payload {
            identifiers: None,
            csr: None,
            terms_of_service_agreed: Some(true),
            external_account_binding,
            contact: Some(vec![format!("mailto:{}", email)]),
        })
    }
    fn _new_order(dns: &Vec<String>) -> Option<Self> {
        let list: Vec<Identifier> = dns.iter().map(|s| Identifier::new(s.to_string())).collect();
        Some(Payload {
            identifiers: Some(list),
            terms_of_service_agreed: None,
            external_account_binding: None,
            contact: None,
            csr: None,
        })
    }
    fn _new_authz() -> Option<Self> {
        None
    }
    fn _new_chall() -> Option<Self> {
        Some(Payload {
            identifiers: None,
            terms_of_service_agreed: None,
            external_account_binding: None,
            contact: None,
            csr: None,
        })
    }
    fn _new_csr(csr: String) -> Option<Self> {
        Some(Payload {
            identifiers: None,
            terms_of_service_agreed: None,
            external_account_binding: None,
            contact: None,
            csr: Some(csr),
        })
    }
}

#[derive(Serialize, Debug)]
struct SigBody {
    payload: String,
    protected: String,
    signature: String,
}
impl SigBody {
    pub fn from(payload: Option<Payload>, protected: Protected, file_path: &str) -> Result<Self, AcmeError> {
        Self::new(Self::payload64(payload)?, protected, file_path)
    }

    pub fn new(payload64: String, protected: Protected, file_path: &str) -> Result<Self, AcmeError> {
        let protected_json = serde_json::to_string(&protected).unwrap();
        let protected64 = _base64(protected_json.as_bytes());
        trace!("protected:{}\nprotected64:{}", protected_json, protected64);

        let plain = format!("{}.{}", protected64, payload64);

        let signature = if protected.alg.starts_with("H") {
            _base64_hmac256(file_path, &plain)
        } else {
            _sign_by_cmd_openssl(file_path, &plain, protected.alg.starts_with("E"), &protected.alg[2..])?
        };
        Ok(SigBody {
            payload: payload64,
            protected: protected64,
            signature: signature,
        })
    }

    pub fn to_string(&self) -> Result<Option<String>, AcmeError> {
        Ok(Some(serde_json::to_string(&self)?))
    }
    fn payload64(payload: Option<Payload>) -> Result<String, AcmeError> {
        match payload {
            Some(p) => {
                let payload_json = serde_json::to_string(&p)?;
                //.replace("\":", "\": ");
                let payload64 = _base64(payload_json.as_bytes());
                trace!("payload:{:?}, => \n{}\npayload64:{}", p, payload_json, payload64);
                Ok(payload64)
            }
            None => Ok("".to_string()),
        }
    }
}

#[derive(Deserialize, Debug)]
struct OrderRes {
    identifier: Option<Identifier>,
    status: String,
    //expires: String,
    authorizations: Option<Vec<String>>,
    challenges: Option<Vec<OrderResChall>>,
    finalize: Option<String>,
    certificate: Option<String>,
}
impl OrderRes {
    fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }
}

#[derive(Deserialize, Debug)]
struct OrderResChall {
    #[serde(rename(deserialize = "type"))]
    _type: String,
    url: String,
    status: String,
    token: String,
}

async fn _post_kid(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
    payload: Option<Payload>,
) -> Result<(reqwest::header::HeaderMap, String, u16), AcmeError> {
    let protected = Protected::from_kid(&url, nonce, alg, kid);
    let sig_body = SigBody::from(payload, protected, file_path)?;
    _http_json(&url, sig_body.to_string()?, Method::POST).await
}
async fn _http_json(
    url: &str,
    body: Option<String>,
    method: Method,
) -> Result<(reqwest::header::HeaderMap, String, u16), AcmeError> {
    //let params: HashMap<&str, &str> = [("host", h), ("type", "auto")].into_iter().collect();
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

    let response = cb
        .header("Content-Type", CONTENT_TYPE_JSON)
        .header("User-Agent", USER_AGENT)
        .timeout(TIMEOUT_SEC_10)
        .send()
        .await
        .map_err(AcmeError::from)?;

    let (c, h) = (response.status().as_u16(), response.headers().clone());
    debug!("<== Response: {}, header: {:?}", c, response.headers());

    // if !response.status().is_success() {
    //     warn!("{}", response.text().await?);
    //     AcmeError::tip(&format!("{}Error", c))
    // } else {
    //     let res = response.text().await?;
    //     debug!("<== Response: {}", res);
    //     Ok((h, res))
    // }
    let res = response.text().await?;
    debug!("<== Response: {}", res);
    Ok((h, res, c))
    //Ok(response)
}

// GET https://acme-v02.api.letsencrypt.org/directory
// curl https://acme-v02.api.letsencrypt.org/directory -ik
async fn _directory(url: String) -> Result<Directory, AcmeError> {
    let res = _http_json(&url, None, Method::GET).await?.1;
    trace!("Directory: {}", res);
    let dir: Directory = serde_json::from_str(&res)?;
    Ok(dir)
}

fn _get_header(key: &str, headers: &reqwest::header::HeaderMap) -> String {
    for (k, v) in headers {
        if k.as_str() == key {
            return v.to_str().unwrap().to_string();
        }
    }
    "".to_string()
}

async fn _new_nonce(url: &str) -> Result<String, AcmeError> {
    Ok(_get_header(
        HEADER_REPLAY_NONCE,
        &_http_json(url, None, Method::HEAD).await?.0,
    ))
}

async fn _eab_by_email(url: &str, email: &str, acme_ca_dir: &str) -> Result<Option<Eab>, AcmeError> {
    //cache
    let _cache_path = format!("{}/.cache_{}.eab", acme_ca_dir, email);
    let res = if let Some(s) = _read_cache(&_cache_path) {
        s
    } else {
        let url = format!("{}?email={}", url, email);
        let res = _http_json(&url, None, Method::POST).await?.1;
        let _ = _write_to_file(&_cache_path, &res)?;
        res
    };

    let eab: Eab = serde_json::from_str(&res)?;
    if !eab.success {
        if let Some(_e) = eab.error {
            warn!("{}: {:?} {:?}", _e.code, _e._type, _e.info)
        }
        return AcmeError::tip(TIP_EAB_FAILED);
    }
    Ok(Some(eab))
}

async fn _new_acct(
    url: String,
    nonce: String,
    cfg: &AcmeCfg,
    ak_path: &str,
    alg: &str,
    jwk: Jwk,
) -> Result<(String, String), AcmeError> {
    //let payload_reg = "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6IHRydWV9"; //("termsOfServiceAgreed", true);
    // protected='{"nonce": "5yfKMBJJlBFlOD5krHoGQPfcIGi-ad7Ri5bfCjM2Hnys1Q8WBD8", "url": "https://acme-v02.api.letsencrypt.org/acme/new-acct", "alg": "ES256", "jwk": {"crv": "P-256", "kty": "EC", "x": "JP6zfy5Fey4_6jt6J3Tcq-d5dlK05_4r17OKtMTm6bc", "y": "rDQt-nR5riRjwhDVx5D2IoZZZ9YDyWOaqE2P4GaY0UA"}}'
    // let jwk_alg = _print_key_by_cmd_openssl(&file_path, is_ecc);
    let eab = &cfg.eab;
    let kid = if eab.success {
        &format!(".{}", eab.eab_kid.clone().unwrap())
    } else {
        ""
    };
    let acme_ca_dir = &cfg.acme_ca_dir;
    let _cache_path = format!("{0}{1}{2}", &acme_ca_dir, PATH_CACHE_KID, kid); //cache
    if let Some(s) = _read_cache(&_cache_path) {
        return Ok((nonce, s));
    }

    let payload = if let Some(email) = &cfg.email {
        let eab = if eab.success {
            Eab::_clone(eab)
        } else if let Some(eab_url) = &cfg.ca.eab_url() {
            _eab_by_email(&eab_url, &email, &acme_ca_dir).await?
        } else {
            None
        };
        let osb = if let Some(eab) = eab {
            let eab_payload64 = _base64(jwk.to_string().as_bytes());
            Some(SigBody::new(
                eab_payload64,
                Protected::from_eab(&url, ALG_HMAC_256, &eab.eab_kid.unwrap()),
                &eab.eab_hmac_key.unwrap(),
            )?)
        } else {
            None
        };

        let p = Payload::_new_acct_with_eab(email, osb);
        debug!("with_eab: {:?}", p);
        p
    } else {
        Payload::_new_acct()
    };

    let protected = Protected::from(&url, nonce, alg, jwk);
    let sig_body = SigBody::from(payload, protected, ak_path)?;

    let headers = _http_json(&url, sig_body.to_string()?, Method::POST).await?.0;

    let (nonce, kid) = (
        _get_header(HEADER_REPLAY_NONCE, &headers),
        _get_header(HEADER_LOCATION, &headers),
    );

    let _ = _write_to_file(&_cache_path, &kid)?;

    Ok((nonce, kid))
}

async fn _new_order(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
    dns: &Vec<String>,
) -> Result<(String, OrderRes), AcmeError> {
    let res = _post_kid(url, nonce, file_path, alg, kid, Payload::_new_order(dns)).await?;
    let nonce = _get_header(HEADER_REPLAY_NONCE, &res.0);
    let or_: OrderRes = serde_json::from_str(&res.1)?;
    Ok((nonce, or_))
}

async fn _auth_domain(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
) -> Result<(String, OrderRes), AcmeError> {
    //protected='{"nonce": "I4RLVp83dJs_Cmdyr2DAkMP1a2UeHlIj0oYrOgQiG0B_T0YslvQ", "url": "https://acme-v02.api.letsencrypt.org/acme/authz-v3/366261494877", "alg": "ES256", "kid": "https://acme-v02.api.letsencrypt.org/acme/acct/1792176437"}'
    let res = _post_kid(&url, nonce, file_path, alg, kid, Payload::_new_authz()).await?;
    let nonce = _get_header(HEADER_REPLAY_NONCE, &res.0);
    let or_: OrderRes = serde_json::from_str(&res.1)?;
    Ok((nonce, or_))
}

async fn _write_to_challenges(token: String, domain: &str, acme_dir: &str, thumbprint: &str) -> Result<String, AcmeError> {
    let token = token.replace(r"[^A-Za-z0-9_\-]", "_");
    let key_authorization = format!("{0}.{1}", token, thumbprint);
    let well_known_path = format!("{}{}{}", acme_dir, DIR_CHALLENGES, token);
    let _ = _write_to_file(&well_known_path, &key_authorization)?;
    let wellknown_url = format!("http://{0}/.well-known/acme-challenge/{1}", domain, token);
    let ka = _http_json(&wellknown_url, None, Method::GET).await?.1; // 自己先验一下
    if ka != key_authorization {
        return AcmeError::tip(&format!("Check failed: {}", wellknown_url));
    }
    Ok(well_known_path)
}

async fn _chall_domain(url: &str, nonce: String, file_path: &str, alg: &str, kid: &str) -> Result<(String, bool), AcmeError> {
    //protected='{"nonce": "I4RLVp830DhlbzGGoGqxd90G_wxxqbI25XFqmD1fxqaPMj4H_Os", "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/366261494887/3xX-Gg", "alg": "ES256", "kid": "https://acme-v02.api.letsencrypt.org/acme/acct/1792176437"}'
    let res = _post_kid(&url, nonce, file_path, alg, kid, Payload::_new_chall()).await?;
    let nonce = _get_header(HEADER_REPLAY_NONCE, &res.0);
    if res.2 > 300 {
        return Ok((nonce, false));
    }
    let or_: OrderResChall = serde_json::from_str(&res.1)?;
    Ok((nonce, or_.status == STATUS_OK))
}

async fn _finalize_csr(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
    csr: String,
) -> Result<(String, String, OrderRes), AcmeError> {
    let res = _post_kid(&url, nonce, file_path, alg, kid, Payload::_new_csr(csr)).await?;
    let nonce = _get_header(HEADER_REPLAY_NONCE, &res.0);
    let location = _get_header(HEADER_LOCATION, &res.0);

    let or_: OrderRes = serde_json::from_str(&res.1)?;
    //let a = if or_.status == STATUS_OK { or_.certificate } else { None };
    Ok((nonce, location, or_))
}

async fn _order_status(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
) -> Result<(String, OrderRes), AcmeError> {
    let res = _post_kid(&url, nonce, file_path, alg, kid, None).await?;
    let nonce = _get_header(HEADER_REPLAY_NONCE, &res.0);
    let or_: OrderRes = serde_json::from_str(&res.1)?;

    Ok((nonce, or_))
}

async fn _down_certificate(url: &str, nonce: String, file_path: &str, alg: &str, kid: &str) -> Result<String, AcmeError> {
    Ok(_post_kid(&url, nonce, file_path, alg, kid, None).await?.1)
}

fn _base64_hmac256(key: &str, s: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&URL_SAFE.decode(_durl_base64(key)).unwrap()).expect("...");
    mac.update(s.as_bytes());
    _base64(&mac.finalize().into_bytes())
}

fn _durl_base64(input: &str) -> String {
    let padding = match input.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let mut output = input.to_string();
    output.push_str(padding);
    output.replace("_-", "+/")
}

fn _base64(s: &[u8]) -> String {
    URL_SAFE.encode(s).replace("=", "")
}

fn _base64_hex(hex_str: &str) -> String {
    _base64(&hex::decode(hex_str).unwrap())
}
fn _base64_sha256(p: &str) -> String {
    //let p = r#"{"crv":"P-256","kty":"EC","x":"MysViqQWRtiId88Tr5-PkZzLQ64WagPZF_WFPJk_LIE","y":"WByhhlb7q50I-uXme6YSG042gMslQuiy1st36FUn3MQ"}"#;
    let mut hasher = Sha256::new();
    hasher.update(p.as_bytes());
    let hash = hasher.finalize();
    let b64_hash = _base64(&hash);
    trace!("sha2 sha256 base64: {}", b64_hash);
    b64_hash
}

fn _gen_key_by_cmd_openssl(key_path: &str, alg: &Alg) -> Result<Output, AcmeError> {
    let a: Vec<&str> = match alg {
        Alg::RSA2048 => vec!["genrsa", "-out", key_path, "2048"],
        Alg::RSA4096 => vec!["genrsa", "-out", key_path, "4096"],
        Alg::ECC256 => vec!["ecparam", "-name", "prime256v1", "-genkey", "-out", key_path],
        Alg::ECC384 => vec!["ecparam", "-name", "secp384r1", "-genkey", "-out", key_path],
    };

    let out = Command::new("openssl").args(a).output()?;
    Ok(out)
}

// echo "[SAN]\nsubjectAltName=$DNS" > openssl.cnf.1.tmp
// cat /etc/ssl/openssl.cnf openssl.cnf.1.tmp > openssl.cnf.tmp
// openssl req -new -key domain.key -subj "/" -reqexts SAN -config openssl.cnf.tmp  > domain.csr
fn _gen_csr_by_cmd_openssl(acme_dir: &str, domain_key_alg: &Alg, dns: &Vec<String>) -> Result<(String, String), AcmeError> {
    let domain_key_path = format!("{0}/{1}", acme_dir, DOMAIN_KEY);
    let domain_csr_path = format!("{}/domain.csr", acme_dir);
    let tmp = format!("{}/openssl.cnf.tmp", acme_dir);

    let _ = _gen_key_by_cmd_openssl(&domain_key_path, &domain_key_alg);
    debug!("Successfully. Gen domain key by {:?}: {}", &domain_key_alg, &domain_key_path);

    let openssl_cnf = fs::read_to_string("/etc/ssl/openssl.cnf")?;
    let dns_san = dns.iter().map(|_d| format!("DNS:{}", _d)).collect::<Vec<String>>().join(",");
    let _ = _write_to_file(&tmp, &format!("{}\n[SAN]\nsubjectAltName={}", openssl_cnf, dns_san))?;

    let a =
        ["req", "-new", "-key", &domain_key_path, "-subj", "/", "-reqexts", "SAN", "-config", &tmp, "-out", &domain_csr_path];
    let out = Command::new("openssl").args(a).output()?;
    trace!("{:?}", out);

    let b = ["req", "-in", &domain_csr_path, "-outform", "DER"];
    let out = Command::new("openssl").args(b).output()?;
    let out = _base64(&out.stdout);
    trace!("{}", out);

    Ok((out, domain_key_path))
}

// 覆盖写入
fn _write_to_file(file_path: &str, s: &str) -> Result<(), AcmeError> {
    let _ = File::create(&file_path)
        .map_err(|_e| AcmeError::Tip(format!("Create file failed: {}. {}", file_path, _e.to_string())))?
        .write(s.as_bytes())
        .map_err(|_| AcmeError::Tip(format!("Write failed: {}", file_path)));
    debug!("Write to {}", file_path);
    Ok(())
}

fn _print_key_by_cmd_openssl(account_key_path: &str, is_ecc: bool) -> Result<Jwk, AcmeError> {
    let alg = if is_ecc { "ec" } else { "rsa" };
    let out = Command::new("openssl")
        .args([alg, "-in", account_key_path, "-noout", "-text"])
        .output()?;
    let out = String::from_utf8(out.stdout).unwrap();
    trace!("out: \n{}", &out);

    Jwk::call(&out, is_ecc)
}

fn _sign_by_cmd_openssl(account_key_path: &str, plain: &str, is_ecc: bool, alg_len: &str) -> Result<String, AcmeError> {
    let sha = format!("-sha{}", &alg_len);
    let mut child = Command::new("openssl")
        .args(&["dgst", &sha, "-sign", &account_key_path])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped()) // 捕获输出
        .spawn()?;

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(&plain.as_bytes())?
    }

    trace!(
        "echo \"{}\" | openssl dgst -sha256 -sign {} {} | openssl base64",
        &plain,
        &account_key_path,
        if is_ecc { "| openssl asn1parse -inform DER" } else { "" }
    );

    let out = child.wait_with_output()?;
    if is_ecc {
        let mut child = Command::new("openssl")
            .args(&["asn1parse", "-inform", "DER"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()) // 捕获输出
            .spawn()?;

        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin.write_all(&out.stdout)?
        }
        let out = child.wait_with_output()?;
        let out = String::from_utf8(out.stdout).unwrap();
        trace!("sign ecc out:\n{}", &out);

        Ok(_base64_hex(&_asn1_parse(&out)))
    } else {
        let out = _base64(&out.stdout);
        trace!("sign rsa out: {}", &out);
        Ok(out)
    }
}

/*
    0:d=0  hl=2 l=  70 cons: SEQUENCE
    2:d=1  hl=2 l=  33 prim: INTEGER           :9A610C19E73BE8EC7E9BDD8E87B8263BFEA000AA37CFB30A893CD8BC2CA0A3F7
   37:d=1  hl=2 l=  33 prim: INTEGER           :CE3F47012A7EB61095338B38D95B18E7CDB2EEFFA2BA26E83B226B9C58370A21
*/
fn _asn1_parse(text: &str) -> String {
    let re = Regex::new(r"prim: INTEGER\s*:\s*(\w+)").unwrap();
    let ec_r = re.captures(text).unwrap().get(1).map_or("", |m| m.as_str());
    let ec_s = re
        .captures_iter(text)
        .nth(1)
        .and_then(|cap| cap.get(1))
        .map_or("", |m| m.as_str());

    trace!("ec_r: {}\nec_s: {}", ec_r, ec_s);

    format!("{}{}", ec_r, ec_s)
}

fn _regx(out: &str, reg: &str, need_rep: bool) -> String {
    let non_greedy_re = Regex::new(reg).unwrap();
    let p = non_greedy_re.captures(&out).unwrap().get(1).map_or("", |m| m.as_str());
    if need_rep {
        return p.replace(":", "").replace("\n", "").replace(" ", "");
    }
    p.to_string()
}

fn _read_cache(_cache_path: &str) -> Option<String> {
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
