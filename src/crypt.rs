use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use hmac::{Hmac, Mac};
use log::{debug, trace, warn};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

use crate::{write_file, AcmeError, Alg, CERT_BEGIN, CERT_REGEX, DOMAIN_KEY, ISSUER_REGEX, TIP_REGEX_FAILED};

pub fn base64_hmac256(key: &str, s: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&URL_SAFE.decode(_durl_base64(key)).unwrap()).expect("...");
    mac.update(s.as_bytes());
    base64(&mac.finalize().into_bytes())
}
pub fn hmac256(key: &[u8], s: &str) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("...");
    mac.update(s.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn hex_hmac256(key: &[u8], s: &str) -> String {
    hex::encode(hmac256(key, s))
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

pub fn base64(s: &[u8]) -> String {
    URL_SAFE.encode(s).replace("=", "")
}

pub fn base64_hex(hex_str: &str) -> String {
    base64(&hex::decode(hex_str).unwrap())
}
pub fn base64_sha256(p: &str) -> String {
    //let p = r#"{"crv":"P-256","kty":"EC","x":"MysViqQWRtiId88Tr5-PkZzLQ64WagPZF_WFPJk_LIE","y":"WByhhlb7q50I-uXme6YSG042gMslQuiy1st36FUn3MQ"}"#;
    let mut hasher = Sha256::new();
    hasher.update(p.as_bytes());
    let hash = hasher.finalize();
    let b64_hash = base64(&hash);
    trace!("sha2 sha256 base64: {}", b64_hash);
    b64_hash
}
pub fn sha256(p: &str) -> String {
    //let p = r#"{"crv":"P-256","kty":"EC","x":"MysViqQWRtiId88Tr5-PkZzLQ64WagPZF_WFPJk_LIE","y":"WByhhlb7q50I-uXme6YSG042gMslQuiy1st36FUn3MQ"}"#;
    let mut hasher = Sha256::new();
    hasher.update(p.as_bytes());
    let hash = hasher.finalize();
    let hex_hash = hex::encode(&hash);
    trace!("sha2 sha256 hex: {}", hex_hash);
    hex_hash
}

pub fn gen_key_by_cmd_openssl(alg: &Alg) -> Result<Vec<u8>, AcmeError> {
    let a: Vec<&str> = match alg {
        Alg::RSA2048 => vec!["genrsa", "2048"],
        Alg::RSA4096 => vec!["genrsa", "4096"],
        Alg::ECC256 => vec!["ecparam", "-name", "prime256v1", "-genkey"],
        Alg::ECC384 => vec!["ecparam", "-name", "secp384r1", "-genkey"],
    };

    let out = Command::new("openssl").args(a).output()?;
    Ok(out.stdout)
}

// echo "[SAN]\nsubjectAltName=$DNS" > openssl.cnf.1.tmp
// cat /etc/ssl/openssl.cnf openssl.cnf.1.tmp > openssl.cnf.tmp
// openssl req -new -key domain.key -subj "/" -reqexts SAN -config openssl.cnf.tmp  > domain.csr
pub fn gen_csr_by_cmd_openssl(acme_dir: &str, domain_key_alg: &Alg, dns: &Vec<String>) -> Result<(String, String), AcmeError> {
    let domain_key_path = format!("{0}/{1}", acme_dir, DOMAIN_KEY);
    let domain_csr_path = format!("{}/domain.csr", acme_dir);
    let tmp = format!("{}/openssl.cnf.tmp", acme_dir);

    let _ = write_file(&domain_key_path, &gen_key_by_cmd_openssl(&domain_key_alg)?)?;
    debug!("Successfully. Gen domain key by {:?}: {}", &domain_key_alg, &domain_key_path);

    let openssl_cnf = fs::read_to_string("/etc/ssl/openssl.cnf")?;
    let dns_san = dns.iter().map(|_d| format!("DNS:{}", _d)).collect::<Vec<String>>().join(",");
    let dns_san = format!("{}\n[SAN]\nsubjectAltName={}", openssl_cnf, dns_san);
    let _ = write_file(&tmp, &dns_san.as_bytes())?;

    let a =
        ["req", "-new", "-key", &domain_key_path, "-subj", "/", "-reqexts", "SAN", "-config", &tmp, "-out", &domain_csr_path];
    let out = Command::new("openssl").args(a).output()?;
    trace!("{:?}", out);

    let b = ["req", "-in", &domain_csr_path, "-outform", "DER"];
    let out = Command::new("openssl").args(b).output()?;
    let csr = base64(&out.stdout);
    trace!("{}", csr);

    Ok((csr, domain_key_path))
}

// 分隔，第一个是domain.crt
pub fn split_cert_chained(crt_str: &str) -> Result<String, AcmeError> {
    if crt_str.matches(CERT_BEGIN).count() == 1 {
        warn!("Not full chained crt");
        return Ok(crt_str.to_string());
    }
    Ok(regx1(crt_str, CERT_REGEX)?)
}

pub fn print_key_by_cmd_openssl(account_key_path: &str, is_ecc: bool) -> Result<String, AcmeError> {
    let alg = if is_ecc { "ec" } else { "rsa" };
    let out = Command::new("openssl")
        .args([alg, "-in", account_key_path, "-noout", "-text"])
        .output()?;
    let out = String::from_utf8(out.stdout).unwrap();
    trace!("out: \n{}", &out);

    Ok(out)
}

pub fn sign_by_cmd_openssl(account_key_path: &str, plain: &str, is_ecc: bool, alg_len: &str) -> Result<String, AcmeError> {
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

        Ok(base64_hex(&_asn1_parse(&out)?))
    } else {
        let out = base64(&out.stdout);
        trace!("sign rsa out: {}", &out);
        Ok(out)
    }
}

pub fn issuer_cmd_openssl(cert: &str) -> Result<String, AcmeError> {
    let intermediate_cert = regx2(&cert, CERT_REGEX)?;
    //debug!("Show intermediate cert:\n{}", &intermediate_cert);
    x509_one_cmd_openssl(&intermediate_cert)
}
// openssl crl2pkcs7 -nocrl -certfile ca.crt | openssl pkcs7 -print_certs -text -noout
// openssl crl2pkcs7 -nocrl -certfile ca.crt > ca.pk7
// openssl pkcs7 -print_certs -in ca.pk7 -text -noout
pub fn x509_one_cmd_openssl(cert: &str) -> Result<String, AcmeError> {
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

    let issuer = regx1(&out, ISSUER_REGEX)?.to_uppercase();
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
    let (ec_r, ec_s) = (regx1(text, re)?, regx2(text, re)?);

    trace!("ec_r: {}\nec_s: {}", ec_r, ec_s);

    Ok(format!("{}{}", ec_r, ec_s))
}

pub fn regx2(text: &str, reg: &str) -> Result<String, AcmeError> {
    let non_greedy_re = Regex::new(reg)?;
    let p = non_greedy_re
        .captures_iter(text)
        .nth(1)
        .and_then(|cap| cap.get(1))
        .map_or("", |m| m.as_str());
    Ok(p.to_string())
}
pub fn regx1(text: &str, reg: &str) -> Result<String, AcmeError> {
    regx(text, reg, false)
}
pub fn regx(text: &str, reg: &str, need_rep: bool) -> Result<String, AcmeError> {
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

pub fn extract_simple_root_domain(domain: &str) -> Option<String> {
    let re = Regex::new(r"(?i)(?:^|\.)([a-z0-9-]+\.(com|net|org|io|cn|edu|gov|info|biz|[a-z]{2,})(?:\.[a-z]{2})?)$").unwrap();
    // 匹配并提取一级域名，生成泛域名，如*.a.com
    if re.is_match(domain) {
        if let Some(captures) = re.captures(domain) {
            return captures.get(1).map(|m| format!("*.{}", m.as_str()));
        }
    }
    None
}
