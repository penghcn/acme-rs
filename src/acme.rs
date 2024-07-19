use crate::{
    create_dir, crypt::*, read_cache, write_file, ALG_HMAC_256, CHAINED_CRT, DIR_BACKUP, DIR_CHALLENGE, DOMAIN_CRT,
    DOMAIN_SSL3, MAX_TRY, SLEEP_DURATION_SEC_2, SLEEP_DURATION_SEC_5,
};
use crate::{
    AcmeCfg, AcmeError, Alg, Eab, ACCOUNT_ALG_DEFAULT_EC2, PATH_ACCOUNT_KEY, PATH_CACHE_KID, PUB_ECC_REGEX, PUB_RSA_REGEX,
};

use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CONTENT_TYPE_JSON: &str = "application/jose+json";
const USER_AGENT: &str = "acme.rs";
const TIMEOUT_SEC_10: Duration = Duration::from_secs(10); //10s

const LINK_ALT_REGEX: &str = "<(http.*)>;rel=\"alternate\"";
const HEADER_REPLAY_NONCE: &str = "replay-nonce";
const HEADER_LOCATION: &str = "location";
const HEADER_LINK: &str = "link";
const TYPE_HTTP: &str = "http-01";
const STATUS_OK: &str = "valid"; //valid. pending, ready, processing. invalid
const STATUS_PENDING: &str = "pending"; //valid. pending, ready, processing. invalid
const TIP_REQUIRED_EMAIL: &str = "Required email, add param like: email=a@a.org";
const TIP_DOWN_CRT_FAILED: &str = "Download certificate failed, exiting.";
const TIP_MAX_TRY: &str = "Maximum attempts reached, exiting.";
const TIP_EAB_FAILED: &str = "Get Eab Fialed.";
const TIP_ACCOUNT_FAILED: &str = "Get Acccount Fialed.";
const TIP_TYPE_HTTP_FAILED: &str = "Get challenges http-01 Fialed.";

pub async fn acme_issue(cfg: &AcmeCfg) -> Result<Vec<String>, AcmeError> {
    // 1 初始化参数，获取或者默认值
    info!("Step 1 Init Params: {:?}", cfg);

    // 2 获取接口  /directory
    let dir = _directory(cfg.ca.directory_url()).await?;
    info!("Step 2 GET Directory. {:?}", dir);
    let required_external_account = dir.meta.external_account_required.unwrap_or(false);

    // 2.1 是否需要扩展账户信息eab，目前就是zerossl,gts
    if required_external_account & cfg.email.is_none() {
        return AcmeError::tip(TIP_REQUIRED_EMAIL);
    }

    // 3.1 先获取或生成 account.key，默认ecc256
    let account_key_path = format!("{0}{1}", cfg.acme_ca_dir, PATH_ACCOUNT_KEY);
    let account_alg = Alg::new(ACCOUNT_ALG_DEFAULT_EC2); //cfg.alg;

    if read_cache(&account_key_path).is_none() {
        let _ = write_file(&account_key_path, &gen_key_by_cmd_openssl(&account_alg)?);
        let kid_cache_path = format!("{0}{1}{2}", cfg.acme_ca_dir, PATH_CACHE_KID, &cfg.eab._kid());
        let kid_cache_path = Path::new(&kid_cache_path);
        if kid_cache_path.exists() {
            fs::remove_file(kid_cache_path)?; //同时删除cache.kid
        }
        info!("Step 3.1 Gen account key by {:?}: {}", &account_alg, &account_key_path);
    }

    let jwk = print_key_by_cmd_openssl(&account_key_path, account_alg.is_ecc())?;
    let jwk = Jwk::call(&jwk, account_alg.is_ecc())?;
    let alg = jwk.alg();
    let thumbprint = base64_sha256(&jwk.to_string()?);
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
    let (csr, _domain_key_path) = gen_csr_by_cmd_openssl(&cfg.acme_ca_dir, &cfg.domain_alg, &cfg.dns)?;

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
    let _ = x509_one_cmd_openssl(&domain_crt)?;

    // 4.5 合并sign.crt和intermediate.pem的内容成 chained.pem
    let domain_crt_path = format!("{}/{}", cfg.acme_ca_dir, DOMAIN_CRT);
    let chained_pem_path = format!("{}/{}", cfg.acme_ca_dir, CHAINED_CRT);
    info!("Step 4.5 Wirte to {} and {}", DOMAIN_CRT, CHAINED_CRT);

    let (domain_pem, chained_pem) = match cfg.ca.intermediate_url(cfg.domain_alg.is_ecc()) {
        Some(_url) => {
            info!("Download ca intermediate file. Named intermediate.pem");
            let _intermediate_pem = _http_json(&_url, None, Method::GET).await?.1;
            (&domain_crt, &format!("{0}\n{1}", &domain_crt, _intermediate_pem))
        }
        None => (&split_cert_chained(&domain_crt)?, &domain_crt),
    };
    let _ = write_file(&domain_crt_path, &domain_pem.as_bytes())?;
    let _ = write_file(&chained_pem_path, &chained_pem.as_bytes())?;

    // 5 备份、复制
    _ssl_and_backup(&cfg.ssl_dir, &cfg.acme_ca_dir)
}

fn _ssl_and_backup(ssl_dir: &str, acme_ca_dir: &str) -> Result<Vec<String>, AcmeError> {
    // 复制小文件到备份目录
    let bk_no = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let bk_dir = format!("{0}{1}", acme_ca_dir, DIR_BACKUP);

    info!("Step 5.1 Backup to: {}", &bk_dir);
    let _ = create_dir(&bk_dir);

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

    let res = response.text().await?;
    debug!("<== Response: {}", res);
    Ok((h, res, c))
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
    headers
        .iter()
        .filter(|(k, _)| k.as_str() == key)
        .filter_map(|(_, v)| v.to_str().ok().map(|s| s.to_string()))
        .collect()
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
    let res = if let Some(s) = read_cache(&_cache_path) {
        s
    } else {
        let url = format!("{}?email={}", url, email);
        let res = _http_json(&url, None, Method::POST).await?.1;
        let _ = write_file(&_cache_path, &res.as_bytes())?;
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
    if let Some(s) = read_cache(&_cache_path) {
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
            let eab_payload64 = base64(jwk.to_string()?.as_bytes());
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

    let _ = write_file(&_cache_path, &kid.as_bytes())?;

    Ok((nonce, kid))
}

async fn _new_order(
    url: &str,
    nonce: String,
    file_path: &str,
    alg: &str,
    kid: &str,
    dns: &[String],
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
    let well_known_dir = format!("{}{}", acme_dir, DIR_CHALLENGE);
    let _ = create_dir(&well_known_dir);
    let well_known_path = format!("{}{}", well_known_dir, token);

    let _ = write_file(&well_known_path, &key_authorization.as_bytes())?;
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
        let issuer = issuer_cmd_openssl(&cert)?;
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
            .map(|s| regx1(&s, LINK_ALT_REGEX))
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
    fn from(url: &'a str, nonce: String, alg: &'a str, jwk: Jwk) -> Self {
        Protected {
            url,
            nonce: Some(nonce),
            alg,
            jwk: Some(jwk),
            kid: None,
        }
    }
    fn from_kid(url: &'a str, nonce: String, alg: &'a str, kid: &'a str) -> Self {
        Protected {
            url,
            nonce: Some(nonce),
            alg,
            jwk: None,
            kid: Some(kid),
        }
    }
    fn from_eab(url: &'a str, alg: &'a str, kid: &'a str) -> Self {
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
    fn new(value: String) -> Self {
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
    fn _new_order(dns: &[String]) -> Option<Self> {
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
    fn from(payload: Option<Payload>, protected: Protected, file_path: &str) -> Result<Self, AcmeError> {
        Self::new(Self::payload64(payload)?, protected, file_path)
    }

    fn new(payload64: String, protected: Protected, file_path: &str) -> Result<Self, AcmeError> {
        let protected_json = serde_json::to_string(&protected).unwrap();
        let protected64 = base64(protected_json.as_bytes());
        trace!("protected:{}\nprotected64:{}", protected_json, protected64);

        let plain = format!("{}.{}", protected64, payload64);

        let signature = if protected.alg.starts_with("H") {
            base64_hmac256(file_path, &plain)
        } else {
            sign_by_cmd_openssl(file_path, &plain, protected.alg.starts_with("E"), &protected.alg[2..])?
        };
        Ok(SigBody {
            payload: payload64,
            protected: protected64,
            signature: signature,
        })
    }

    fn to_string(&self) -> Result<Option<String>, AcmeError> {
        Ok(Some(serde_json::to_string(&self)?))
    }
    fn payload64(payload: Option<Payload>) -> Result<String, AcmeError> {
        match payload {
            Some(p) => {
                let payload_json = serde_json::to_string(&p)?;
                //.replace("\":", "\": ");
                let payload64 = base64(payload_json.as_bytes());
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

#[derive(Debug)]
enum Method {
    POST,
    GET,
    HEAD,
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
            let pub_ = regx(&out, PUB_ECC_REGEX, true)?;
            let crv = regx1(&out, r"NIST CURVE: (.*)")?;

            let offset = pub_.len() / 2 + 1;
            let (x, y) = (base64_hex(&pub_[2..offset]), base64_hex(&pub_[offset..]));
            Ok(Self::_Ecc(JwkEcc::new(crv, x, y)))
        } else {
            let pub_ = regx(&out, PUB_RSA_REGEX, true)?;
            let e = regx1(&out, r"0x([A-Fa-f0-9]+)")?;
            let e = if e.len() % 2 == 0 { e } else { format!("0{}", e) };
            println!("{}: {}", &e, &pub_);

            let (e64, n) = (base64_hex(&e), base64_hex(&pub_));

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
