use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use chrono::{Duration as ChronoDuration, Local, NaiveDateTime, TimeZone};
use hmac::{Hmac, Mac};
use log::{debug, error, info, trace, warn, Level, LevelFilter, Log, Record};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
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
const LINK_ALT_REGEX: &str = "<(http.*)>;rel=\"alternate\"";

const PUB_ECC_REGEX: &str = r"pub:\n\s+([0-9a-fA-F:]+(?:\n\s+[0-9a-fA-F:]+)*)";
const PUB_RSA_REGEX: &str = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)";

const CRON_DEFAULT_DAYS: i64 = 88; //每隔88天
const CRON_DEFAULT_HOUR: u32 = 0; //下一次0点执行
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
const HEADER_LINK: &str = "link";
const TYPE_HTTP: &str = "http-01";
const STATUS_OK: &str = "valid"; //valid. pending, ready, processing. invalid
const STATUS_PENDING: &str = "pending"; //valid. pending, ready, processing. invalid

const TIP_MISSING_DNS: &str = "Missing parameter 'dns'";
const TIP_MISSING_DIR: &str = "Missing parameter 'dir'";
const TIP_INVALID_DNS: &str = "Wildcard domain names like *.a.com are not supported. Exactly, such as: dns=ai8.rs,www.ai8.rs";
const TIP_REQUIRED_EMAIL: &str = "Required email, add param like: email=a@a.org";
const TIP_DOWN_CRT_FAILED: &str = "Download certificate failed, exiting.";
const TIP_MAX_TRY: &str = "Maximum attempts reached, exiting.";
const TIP_EAB_FAILED: &str = "Get Eab Fialed.";
const TIP_ACCOUNT_FAILED: &str = "Get Acccount Fialed.";
const TIP_TYPE_HTTP_FAILED: &str = "Get challenges http-01 Fialed.";
const TIP_REGEX_FAILED: &str = "Match Regex Fialed.";

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
            error!("{}", _e.to_string());
            return; //中断
        }
        Ok(cfg) => cfg,
    };

    // set log
    log::set_max_level(cfg.log_level);

    // quartz
    // let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(90 * 24 * 60 * 60)); //90天
    // loop {
    //     interval.tick().await;
    //     let _ = acme_issue3(&cfg).await;
    // }

    if let Err(_e) = _simple_cron(&cfg, CRON_DEFAULT_DAYS, CRON_DEFAULT_HOUR).await {
        error!("{}", _e.to_string());
    }
}

async fn _simple_cron(cfg: &AcmeCfg, days: i64, hour: u32) -> Result<(), AcmeError> {
    let mut next_execution = Local::now().naive_local(); //_next_execution(Utc::now().naive_utc(), days, hour);
    loop {
        let future = sleep_until(_tokio_instant(next_execution)?);
        tokio::pin!(future);
        future.await;

        let _ = acme_issue3(&cfg).await;

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

async fn acme_issue3(cfg: &AcmeCfg) -> () {
    // retry 2
    for i in 0..3 {
        match acme_issue(&cfg).await {
            Err(_e) => error!("{}", _e.to_string()),
            Ok(paths) => {
                info!(
        		"Successfully.\nFor Nginx configuration:\n\tssl_certificate {1}\n\tssl_certificate_key {2}
        		\nFor Apache configuration:\n\tSSLEngine on\n\tSSLCertificateFile {0}\n\tSSLCertificateKeyFile {1}\n\tSSLCertificateChainFile {2}",
        		&paths[0], &paths[1], &paths[2]
        	);
                return;
            }
        }
        debug!("Loop {}/3, acme issue", i + 1);
        std::thread::sleep(SLEEP_DURATION_SEC_5);
    }
}

async fn acme_issue(cfg: &AcmeCfg) -> Result<Vec<String>, AcmeError> {
    // 0 初始化参数，获取或者默认值
    info!("Step 1 Init Params: {:?}", cfg);

    // 1 获取接口  /directory
    let dir = _directory(cfg.ca.directory_url()).await?;
    info!("Step 2 GET Directory. {:?}", dir);
    let required_external_account = dir.meta.external_account_required.unwrap_or(false);

    // 1.1 是否需要扩展账户信息eab，目前就是zerossl,gts
    if required_external_account & cfg.email.is_none() {
        return AcmeError::tip(TIP_REQUIRED_EMAIL);
    }

    // 3.1 先获取或生成 account.key，默认ecc256
    let account_key_path = format!("{0}{1}", cfg.acme_ca_dir, PATH_ACCOUNT_KEY);
    let account_alg = Alg::new(ACCOUNT_ALG_DEFAULT_EC2); //cfg.alg;

    if _read_cache(&account_key_path).is_none() {
        let _ = _gen_key_by_cmd_openssl(&account_key_path, &account_alg);
        let kid_cache_path = format!("{0}{1}{2}", cfg.acme_ca_dir, PATH_CACHE_KID, &cfg.eab._kid());
        let kid_cache_path = Path::new(&kid_cache_path);
        if kid_cache_path.exists() {
            fs::remove_file(kid_cache_path)?; //同时删除cache.kid
        }
        info!("Step 3.1 Gen account key by {:?}: {}", &account_alg, &account_key_path);
    }

    let jwk = _print_key_by_cmd_openssl(&account_key_path, account_alg.is_ecc())?;
    let alg = jwk.alg();
    let thumbprint = _base64_sha256(&jwk.to_string()?);
    debug!("\njwk: {:?}, thumbprint:{}", jwk, thumbprint);

    // 3.2 获取nonce接口  /acme/new-nonce
    info!("Step 3.2 POST new nonce.");
    let nonce = _new_nonce(&dir.new_nonce).await?;

    // 3.3 注册账号接口 /acme/new-acct
    //let email = if external_account_required { cfg.email } else { None };
    //let email = cfg.email.filter(|_| external_account_required);
    let (nonce, kid) = _new_acct(dir.new_account, nonce, &cfg, &account_key_path, &alg, jwk).await?;
    info!("Step 3.3 GET account: {}", kid);

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

        let (is_ok, is_pending) = (auth_order_res.is_ok(), auth_order_res.is_pending());
        let (domain, challenges) = (auth_order_res.identifier.unwrap().value, auth_order_res.challenges.unwrap());
        if is_ok {
            info!("Verifyed {0}", domain);
            continue;
        }

        if !is_pending {
            let mut attempts: u8 = 0; //轮询auth
            loop {
                let (nonce, auth_order_res) = _auth_domain(&_authz_url, mut_nonce, &account_key_path, &alg, &kid).await?;
                mut_nonce = nonce;
                if auth_order_res.is_ok() || auth_order_res.is_pending() {
                    break;
                }
                attempts += 1;

                if attempts == MAX_TRY {
                    return AcmeError::tip(TIP_MAX_TRY);
                }
                let _ = std::thread::sleep(SLEEP_DURATION_SEC_2);
                debug!("Loop {}/{}, auth domain", attempts, MAX_TRY);
            }
        }

        info!("Verifying {0}...", domain);
        let chall = challenges.into_iter().filter(|c| c._type == TYPE_HTTP).next();
        let chall = match chall {
            Some(chall) => chall,
            None => return AcmeError::tip(TIP_TYPE_HTTP_FAILED),
        };

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
    // domain key 算法默认ECC384，通过参数指定(参考enum Alg)，目前支持 rsa2048,rsa4096,prime256v1,prime384v1
    let (csr, _domain_key_path) = _gen_csr_by_cmd_openssl(&cfg.acme_ca_dir, &cfg.domain_alg, &cfg.dns)?;

    info!("Step 4.3 Finalize domain with csr.");
    let fin_url = &order_res.finalize.unwrap();
    let (nonce, os_url, or) = _finalize_csr(fin_url, mut_nonce, &account_key_path, &alg, &kid, csr.clone()).await?;
    mut_nonce = nonce;

    let cert_url: Option<String>;
    if or.is_ok() {
        cert_url = or.certificate;
    } else {
        let mut attempts: u8 = 0; //轮询
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
    let domain_crt = _down_certificate(&cert_url, mut_nonce, &account_key_path, &alg, &kid, &cfg.preferred_chain).await?;
    let _ = _x509_one_cmd_openssl(&domain_crt)?;

    // 5.1、最后，合并sign.crt和intermediate.pem的内容成 chained.pem
    let domain_crt_path = format!("{}/{}", cfg.acme_ca_dir, DOMAIN_CRT);
    let chained_pem_path = format!("{}/{}", cfg.acme_ca_dir, CHAINED_CRT);
    info!("Step 4.5 Wirte to {} and {}", DOMAIN_CRT, CHAINED_CRT);

    let (domain_pem, chained_pem) = match cfg.ca.intermediate_url(cfg.domain_alg.is_ecc()) {
        Some(_url) => {
            info!("Download ca intermediate file. Named intermediate.pem");
            let _intermediate_pem = _http_json(&_url, None, Method::GET).await?.1;
            (&domain_crt, &format!("{0}\n{1}", &domain_crt, _intermediate_pem))
        }
        None => (&_split_cert_chained(&domain_crt)?, &domain_crt),
    };
    let _ = _write_file(&domain_crt_path, &domain_pem.as_bytes())?;
    let _ = _write_file(&chained_pem_path, &chained_pem.as_bytes())?;

    _ssl_and_backup(&cfg.ssl_dir, &cfg.acme_ca_dir)
}

fn _ssl_and_backup(ssl_dir: &str, acme_ca_dir: &str) -> Result<Vec<String>, AcmeError> {
    // 复制小文件到备份目录
    let bk_no = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let bk_dir = format!("{0}{1}", acme_ca_dir, DIR_BACKUP);

    info!("Step 5.1 Backup to: {}", &bk_dir);
    let bk_dir_path = Path::new(&bk_dir);
    if !bk_dir_path.exists() {
        debug!("Created path: {:?}", bk_dir_path);
        fs::create_dir_all(bk_dir_path)?; // 递归创建目录
    }

    info!("Step 5.2 Copy to: {}", &ssl_dir);
    let mut list: Vec<String> = Vec::new();
    for s in DOMAIN_SSL3 {
        let (from, ssl_path) = (format!("{}/{}", acme_ca_dir, s), format!("{}/{}", ssl_dir, s));
        let _ = fs::copy(&from, &ssl_path)?; //ssl
        let _ = fs::copy(&from, format!("{}/{}.{}", bk_dir, bk_no, s))?; //backup
        list.push(ssl_path);
    }
    Ok(list)
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
    acme_ca_dir: String, //acme运行的ca相关，如一些缓存，如 /www/ai8.rs/.acme/letsencrypt/v02
    ssl_dir: String,     //domin.key,chained.pem等文件复制到指定的证书目录下, 默认/www/ai8.rs/.acme/ssl
    ca: AcmeCa,
    preferred_chain: Option<String>,
    domain_alg: Alg,
    log_level: LevelFilter,
    eab: Eab,
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

        let ssl_dir = map.get("ssl_dir").map(|s| s.to_string()).unwrap_or(acme_dir);
        let _path = Path::new(&acme_ca_dir);
        if !_path.exists() {
            debug!("Create path: {:?}", _path);
            fs::create_dir_all(_path)?; // 递归创建目录
        }

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
        })
    }
}

#[derive(Debug)]
enum AcmeError {
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
    fn to_string(&self) -> String {
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
            let pub_ = _regx(&out, PUB_ECC_REGEX, true)?;
            let crv = _regx1(&out, r"NIST CURVE: (.*)")?;

            let offset = pub_.len() / 2 + 1;
            let (x, y) = (_base64_hex(&pub_[2..offset]), _base64_hex(&pub_[offset..]));
            Ok(Self::_Ecc(JwkEcc::new(crv, x, y)))
        } else {
            let pub_ = _regx(&out, PUB_RSA_REGEX, true)?;
            let e = _regx1(&out, r"0x([A-Fa-f0-9]+)")?;
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
    fn to_string(&self) -> Result<String, AcmeError> {
        Ok(serde_json::to_string(&self)?)
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
    fn is_pending(&self) -> bool {
        self.status == STATUS_PENDING
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
    match _get_headers(key, &headers).get(0) {
        Some(first) => first.to_string(),
        None => "".to_string(),
    }
}

// 多key情况
fn _get_headers(key: &str, headers: &reqwest::header::HeaderMap) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for (k, v) in headers {
        if k.as_str() == key {
            list.push(v.to_str().unwrap().to_string());
        }
    }
    list
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
        let _ = _write_file(&_cache_path, &res.as_bytes())?;
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
    let acme_ca_dir = &cfg.acme_ca_dir;
    let _cache_path = format!("{0}{1}{2}", &acme_ca_dir, PATH_CACHE_KID, eab._kid()); //cache
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
            let eab_payload64 = _base64(jwk.to_string()?.as_bytes());
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

    let res = _http_json(&url, sig_body.to_string()?, Method::POST).await?;
    if res.2 > 300 {
        return AcmeError::tip(TIP_ACCOUNT_FAILED);
    }

    let (nonce, kid) = (_get_header(HEADER_REPLAY_NONCE, &res.0), _get_header(HEADER_LOCATION, &res.0));

    let _ = _write_file(&_cache_path, &kid.as_bytes())?;

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
    let well_known_path = format!("{}{}{}", acme_dir, DIR_CHALLENGE, token);
    if let Some(_path) = Path::new(&well_known_path).parent() {
        if !_path.exists() {
            debug!("Create parent: {:?}", _path);
            fs::create_dir_all(_path)?; // 递归创建目录
        }
    }
    let _ = _write_file(&well_known_path, &key_authorization.as_bytes())?;
    let wellknown_url = format!("http://{0}{1}{2}", domain, DIR_CHALLENGE, token);
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
    if res.2 > 205 {
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

async fn _down_certificate(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
    preferred_chain: &Option<String>,
) -> Result<String, AcmeError> {
    let res = _post_kid(&url, nonce, file_path, alg, kid, None).await?;
    if res.2 != 200 {
        return AcmeError::tip(TIP_DOWN_CRT_FAILED);
    }
    let nonce = _get_header(HEADER_REPLAY_NONCE, &res.0);
    let cert = res.1;

    if let Some(preferred_chain) = preferred_chain {
        let issuer = _issuer_cmd_openssl(&cert)?;
        if preferred_chain == &issuer {
            return Ok(cert);
        }

        debug!("Considered preferred chain:{}", preferred_chain);
        // let mut a: Option<String>= None;
        // for s in _get_headers(HEADER_LINK, &res.0) {
        // 	  match _regx1(&s, LINK_ALT_REGEX) {
        // 		Ok(url) => a= Some(url),
        // 		Err(_) => continue,
        // 	};
        // };
        let url = _get_headers(HEADER_LINK, &res.0)
            .iter()
            .map(|s| _regx1(&s, LINK_ALT_REGEX))
            .find_map(|s| s.ok());

        let url = match url {
            Some(url) => url,
            None => {
                warn!("Not support alternate link, still use the cert by issuer:{}", issuer);
                return Ok(cert);
            }
        };

        //let url = format!("{}/1", url);
        let res = _post_kid(&url, nonce, file_path, alg, kid, None).await?;
        if res.2 != 200 {
            warn!("Not support preferred chain: {}", preferred_chain);
            return Ok(cert);
        }
        Ok(res.1)
    } else {
        return Ok(cert);
    }
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
        Alg::RSA2048 => vec!["genrsa", "2048"],
        Alg::RSA4096 => vec!["genrsa", "4096"],
        Alg::ECC256 => vec!["ecparam", "-name", "prime256v1", "-genkey"],
        Alg::ECC384 => vec!["ecparam", "-name", "secp384r1", "-genkey"],
    };

    let out = Command::new("openssl").args(a).output()?;
    _write_file(key_path, &out.stdout)?;
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
    let dns_san = format!("{}\n[SAN]\nsubjectAltName={}", openssl_cnf, dns_san);
    let _ = _write_file(&tmp, &dns_san.as_bytes())?;

    let a =
        ["req", "-new", "-key", &domain_key_path, "-subj", "/", "-reqexts", "SAN", "-config", &tmp, "-out", &domain_csr_path];
    let out = Command::new("openssl").args(a).output()?;
    trace!("{:?}", out);

    let b = ["req", "-in", &domain_csr_path, "-outform", "DER"];
    let out = Command::new("openssl").args(b).output()?;
    let csr = _base64(&out.stdout);
    trace!("{}", csr);

    Ok((csr, domain_key_path))
}

// 覆盖写入
fn _write_file(file_path: &str, s: &[u8]) -> Result<(), AcmeError> {
    let _ = File::create(&file_path)
        .map_err(|_e| AcmeError::Tip(format!("Create file failed: {}. {}", file_path, _e.to_string())))?
        .write(s)
        .map_err(|_| AcmeError::Tip(format!("Write failed: {}", file_path)));
    debug!("Write to {}", file_path);
    Ok(())
}

// 分隔，第一个是domain.crt
fn _split_cert_chained(crt_str: &str) -> Result<String, AcmeError> {
    if crt_str.matches(CERT_BEGIN).count() == 1 {
        warn!("Not full chained crt");
        return Ok(crt_str.to_string());
    }
    Ok(_regx1(crt_str, CERT_REGEX)?)
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

        Ok(_base64_hex(&_asn1_parse(&out)?))
    } else {
        let out = _base64(&out.stdout);
        trace!("sign rsa out: {}", &out);
        Ok(out)
    }
}

fn _issuer_cmd_openssl(cert: &str) -> Result<String, AcmeError> {
    let intermediate_cert = _regx2(&cert, CERT_REGEX)?;
    //debug!("Show intermediate cert:\n{}", &intermediate_cert);
    _x509_one_cmd_openssl(&intermediate_cert)
}
// openssl crl2pkcs7 -nocrl -certfile ca.crt | openssl pkcs7 -print_certs -text -noout
// openssl crl2pkcs7 -nocrl -certfile ca.crt > ca.pk7
// openssl pkcs7 -print_certs -in ca.pk7 -text -noout
fn _x509_one_cmd_openssl(cert: &str) -> Result<String, AcmeError> {
    let mut child = Command::new("openssl")
        .args(&["x509", "-text", "-noout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped()) // 捕获输出
        .spawn()?;

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(&cert.as_bytes())?
    }
    let out = child.wait_with_output()?;
    let out = String::from_utf8(out.stdout).unwrap();
    debug!("Show X509 first cert:\n{}", &out);

    let issuer = _regx1(&out, ISSUER_REGEX)?.to_uppercase();
    debug!("Issuer:{}", &issuer);

    Ok(issuer)
}

/*
    0:d=0  hl=2 l=  70 cons: SEQUENCE
    2:d=1  hl=2 l=  33 prim: INTEGER           :9A610C19E73BE8EC7E9BDD8E87B8263BFEA000AA37CFB30A893CD8BC2CA0A3F7
   37:d=1  hl=2 l=  33 prim: INTEGER           :CE3F47012A7EB61095338B38D95B18E7CDB2EEFFA2BA26E83B226B9C58370A21
*/
fn _asn1_parse(text: &str) -> Result<String, AcmeError> {
    let re = r"prim: INTEGER\s*:\s*(\w+)";
    //let re = Regex::new(r"prim: INTEGER\s*:\s*(\w+)").unwrap();
    // let ec_r = re.captures(text).unwrap().get(1).map_or("", |m| m.as_str());
    // let ec_s = re
    //     .captures_iter(text)
    //     .nth(1)
    //     .and_then(|cap| cap.get(1))
    //     .map_or("", |m| m.as_str());
    let (ec_r, ec_s) = (_regx1(text, re)?, _regx2(text, re)?);

    trace!("ec_r: {}\nec_s: {}", ec_r, ec_s);

    Ok(format!("{}{}", ec_r, ec_s))
}

fn _regx2(text: &str, reg: &str) -> Result<String, AcmeError> {
    let non_greedy_re = Regex::new(reg)?;
    let p = non_greedy_re
        .captures_iter(text)
        .nth(1)
        .and_then(|cap| cap.get(1))
        .map_or("", |m| m.as_str());
    Ok(p.to_string())
}
fn _regx1(text: &str, reg: &str) -> Result<String, AcmeError> {
    _regx(text, reg, false)
}
fn _regx(text: &str, reg: &str, need_rep: bool) -> Result<String, AcmeError> {
    let non_greedy_re = Regex::new(reg)?;
    if let Some(cap) = non_greedy_re.captures(&text) {
        let p = cap.get(1).map_or("", |m| m.as_str());
        if need_rep {
            return Ok(p.replace(":", "").replace("\n", "").replace(" ", ""));
        }
        Ok(p.to_string())
    } else {
        return AcmeError::tip(TIP_REGEX_FAILED);
    }
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
