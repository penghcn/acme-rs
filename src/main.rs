use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Output, Stdio};

const URL_LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

const URL_ZERO: &str = "https://acme.zerossl.com/v2/DV90";
const _URL_ZERO_EAB: &str = "https://api.zerossl.com/acme/eab-credentials-email";

const URL_BUYPASS: &str = "https://api.buypass.com/acme/directory"; //注意大陆境内，该链接无法访问
const URL_GOOGLE: &str = "https://dv.acme-v02.api.pki.goog/directory"; //注意大陆境内，该链接无法访问

const CA_DEFAULT_LE: &str = "le";
const ALG_DEFAULT_EC3: &str = "EC3";

const REPLAY_NONCE: &str = "replay-nonce";
const TYPE_HTTP: &str = "http-01";
//const TYPE_DNS: &str = "dns-01";
//const TYPE_ALPN: &str = "tls-alpn-01";
const STATUS_OK: &str = "valid"; //valid, pending, invalid

const TIP_REQUIRED_EMAIL: &str = "Required email, add param like: email=a@a.org";

// rm -rf ~/.acme.sh/*
// 参考 sh ./a.sh --issue -d ai8.rs -d www.ai8.rs -d cp.ai8.rs -w ~/www/ai8.rs  --debug 3 --keylength ec-384 --register-account -m my_tmp_email@163.com --server zerossl

#[tokio::main]
async fn main() {
	// 获取所有的命令行参数，跳过第一个参数（程序路径）
	// cargo test --test acme -- _acme --exact --show-output  dns=ai8.rs,www.ai8.rs dir=~/www/pengh/docker_conf/nginx/ssl/le/ai8.rs email=a@a.org ca=z
	// cargo run -- dns=ai8.rs,www.ai8.rs dir=~/www/pengh/docker_conf/nginx/ssl/le/ai8.rs email=a@a.org ca=z

	let args: Vec<String> = std::env::args().skip(1).collect();
	dbg!(&args);

	let _cfg = AcmeCfg::new(args);
	if let Err(_e) = _cfg {
		println!("{:?}", _e);
		return; //中断
	}

	if let Err(_e) = _acme2(_cfg.unwrap()).await {
		println!("{:?}", _e);
	}
}

async fn _acme2(cfg: AcmeCfg) -> Result<(), AcmeError> {
	// 0 初始化参数，获取或者默认值
	println!("Step1 Init Params: {:?}", cfg);
	let dns_ = cfg.dns;
	//let account_key_path_ = "~/www/pengh/docker_conf/nginx/ssl/le/acct.key";
	let account_key_path_ = cfg.account_key_path.as_str();
	let account_key_alg_ = cfg.alg;
	//let file_path = "~/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/account.key";
	let domain_acme_dir_ = cfg.acme_dir;

	// 1 init获取接口  /directory
	let _dir = _directory(cfg.ca.directory_url()).await?;
	println!("\nStep2 GET Directory. {:?}", _dir);
	let external_account_required = _dir.meta.external_account_required.unwrap_or(false);

	// 1.1 是否需要扩展账户信息，目前就是zerossl
	if external_account_required & cfg.email.is_none() {
		return Err(AcmeError::Tip(TIP_REQUIRED_EMAIL.to_string()));
	} else {
		println!("required:{},{:?}", external_account_required, cfg.email);
	}

	// 2 获取nonce接口  /acme/new-nonce
	let _nonce = _new_nonce(&_dir.new_nonce).await?;
	//let nonce = "5yfKMBJJlBFlOD5krHoGQPfcIGi-ad7Ri5bfCjM2Hnys1Q8WBD8";

	// 3

	// 3.1 先获取或生成 account.key, 通过参数指定(参考enum Alg)， 目前支持 rsa2048,rsa4096,prime256v1,prime384v1,prime512v1
	let _ = _gen_key_by_cmd_openssl(&account_key_path_, &account_key_alg_);
	let jwk = _print_key_by_cmd_openssl(&account_key_path_, account_key_alg_.is_ecc());
	let alg = jwk.alg();
	let thumbprint = _base64_sha256(&jwk.to_string());
	println!("\njwk: {:?}, thumbprint:{}", jwk, thumbprint);

	// 3.2 注册账号接口 /acme/new-acct
	//let email = if external_account_required { cfg.email } else { None };
	let email = cfg.email.filter(|_| external_account_required);
	let (_nonce, kid) = _new_acct(_dir.new_account, _nonce, email, account_key_path_, &alg, jwk).await?;
	println!("\nStep3 POST account. {}", _nonce);

	// 4 下单 -> 验证每个域名 -> 验证每个域名
	// 4.1 下单 /acme/new-order
	let (_nonce, _order_res) = _new_order(_dir.new_order, _nonce, &account_key_path_, &alg, &kid, dns_).await?;

	// 4.2 验证每个域名
	let mut _mut_nonce_ = _nonce;
	for _authz_url in _order_res.authorizations.unwrap() {
		let (_nonce, _order_res) = _auth_domain(_authz_url, _mut_nonce_, &account_key_path_, &alg, &kid).await?;
		_mut_nonce_ = _nonce;

		let (_domain, _challenges) = (_order_res.identifier.unwrap().value, _order_res.challenges.unwrap());
		let _chall = _challenges.into_iter().filter(|c| c._type == TYPE_HTTP).next().unwrap();

		_write_to_well_known(_chall.token, &_domain, &domain_acme_dir_, &thumbprint).await?;
		let (_nonce, _ch) = _chall_domain(_chall.url, _mut_nonce_, &account_key_path_, &alg, &kid).await?;
		_mut_nonce_ = _nonce;
	}
	Ok(())
}

trait CA {
	fn directory_url(&self) -> &'static str;
}

struct LetsEncrypt;
struct ZeroSSL;
struct Google;
struct BuyPass;

impl CA for LetsEncrypt {
	fn directory_url(&self) -> &'static str {
		URL_LE
	}
}

impl CA for ZeroSSL {
	fn directory_url(&self) -> &'static str {
		URL_ZERO
	}
}

impl CA for Google {
	fn directory_url(&self) -> &'static str {
		URL_GOOGLE
	}
}

impl CA for BuyPass {
	fn directory_url(&self) -> &'static str {
		URL_BUYPASS
	}
}

enum AcmeCa {
	LetsEncrypt(Box<dyn CA>),
	ZeroSSL(Box<dyn CA>),
	Google(Box<dyn CA>),
	BuyPass(Box<dyn CA>),
}

// 只是简单实现 Debug trait，并不会真实打印。编译器不会再报错
impl std::fmt::Debug for AcmeCa {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AcmeCa::LetsEncrypt(_) => write!(f, "AcmeCa::LetsEncrypt"),
			AcmeCa::ZeroSSL(_) => write!(f, "AcmeCa::ZeroSSL"),
			AcmeCa::Google(_) => write!(f, "AcmeCa::Google"),
			AcmeCa::BuyPass(_) => write!(f, "AcmeCa::BuyPass"),
		}
	}
}

impl AcmeCa {
	fn new(ca_type: &str) -> Self {
		match ca_type {
			CA_DEFAULT_LE => AcmeCa::LetsEncrypt(Box::new(LetsEncrypt)),
			"z" | "zero" => AcmeCa::ZeroSSL(Box::new(ZeroSSL)),
			"b" | "buypass" => AcmeCa::BuyPass(Box::new(BuyPass)),
			"g" | "google" => AcmeCa::Google(Box::new(Google)),
			_ => AcmeCa::LetsEncrypt(Box::new(LetsEncrypt)),
		}
	}

	fn directory_url(&self) -> String {
		self.ca().directory_url().to_string()
	}

	fn ca(&self) -> &dyn CA {
		match self {
			AcmeCa::LetsEncrypt(ca) => ca.as_ref(),
			AcmeCa::ZeroSSL(ca) => ca.as_ref(),
			AcmeCa::Google(ca) => ca.as_ref(),
			AcmeCa::BuyPass(ca) => ca.as_ref(),
		}
	}
}

#[derive(Debug)]
struct AcmeCfg {
	dns: String,
	email: Option<String>,
	acme_dir: String,
	ca: AcmeCa,
	account_key_path: String,
	alg: Alg,
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

		let dns = map
			.get("dns")
			.ok_or_else(|| AcmeError::Tip("Missing parameter 'dns'".to_string()))?
			.to_string();
		let acme_dir = map
			.get("dir")
			.ok_or_else(|| AcmeError::Tip("Missing parameter 'dir'".to_string()))?
			.to_string();

		if !std::path::Path::new(&acme_dir).is_dir() {
			return Err(AcmeError::Tip(format!("The directory does not exist: {}", acme_dir)));
		}

		let account_key_path = format!("{}/.acme/account.key", acme_dir);
		if let Some(parent) = std::path::Path::new(&account_key_path).parent() {
			if !parent.exists() {
				// 递归创建父目录
				println!("Create parent: {:?}", parent);
				std::fs::create_dir_all(parent)?;
			}
		}

		let email = map.get("email").map(|s| s.to_string());
		let ca = AcmeCa::new(map.get("ca").unwrap_or(&CA_DEFAULT_LE));
		let alg = Alg::new(map.get("alg").unwrap_or(&ALG_DEFAULT_EC3));

		Ok(AcmeCfg {
			dns,
			acme_dir,
			email,
			ca,
			account_key_path,
			alg,
		})
	}
}

#[derive(Debug)]
enum AcmeError {
	ReqwestError(reqwest::Error),
	IoError(std::io::Error),
	SerdeJsonError(serde_json::Error),
	Tip(String), // 示例自定义错误
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
impl From<serde_json::Error> for AcmeError {
	fn from(error: serde_json::Error) -> Self {
		AcmeError::SerdeJsonError(error)
	}
}

#[derive(Debug)]
enum Method {
	POST,
	GET,
	HEAD,
	POST_FORM,
}

#[derive(Debug)]
enum Alg {
	RSA2,
	RSA4,
	ECC2,
	ECC3,
	ECC5,
}
impl Alg {
	fn new(alg: &str) -> Self {
		match alg.to_uppercase().as_str() {
			ALG_DEFAULT_EC3 | "ECC3" => Alg::ECC3,
			"EC5" | "ECC5" => Alg::ECC5,
			"EC2" | "ECC2" => Alg::ECC2,
			"RSA4" => Alg::RSA4,
			"RSA2" => Alg::RSA2,
			_ => Alg::ECC3, //default
		}
	}

	fn is_ecc(&self) -> bool {
		matches!(self, Alg::ECC2 | Alg::ECC3 | Alg::ECC5)
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
	terms_of_service: String,
	website: String,
	caa_identities: Vec<String>,
	external_account_required: Option<bool>,
}

#[derive(Deserialize, Debug)]
struct Eab {
	success: bool,
	error: Option<EabError>,
	eab_kid: Option<String>,
	eab_hmac_key: Option<String>,
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

// 参考serde用法详解
// https://blog.wangjunfeng.com/post/2024/rust-serde/#serderename--name-1
#[derive(Serialize, Debug)]
#[serde(untagged)]
enum Jwk {
	_Ecc(JwkEcc),
	_Rsa(JwkRsa),
}
impl Jwk {
	fn call(out: &str, is_ecc: bool) -> Self {
		//let is_ecc= out.starts_with("Private-Key:");
		if is_ecc {
			let pub_ = _regx(&out, r"pub:\n\s+([0-9a-fA-F:]+(?:\n\s+[0-9a-fA-F:]+)*)", true);
			let crv = _regx(&out, r"NIST CURVE: (.*)", false);

			let offset = pub_.len() / 2 + 1;
			let (x, y) = (_base64_hex(&pub_[2..offset]), _base64_hex(&pub_[offset..]));
			Self::_Ecc(JwkEcc::new(crv, x, y))
		} else {
			let pub_ = _regx(
				&out,
				r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)",
				true,
			);
			let e = _regx(&out, r"0x([A-Fa-f0-9]+)", false);
			let e = if e.len() % 2 == 0 { e } else { format!("0{}", e) };
			println!("{}: {}", &e, &pub_);

			let (e64, n) = (_base64_hex(&e), _base64_hex(&pub_));

			Self::_Rsa(JwkRsa::new(e64, n))
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
}

impl Payload {
	fn _new_acct() -> Option<Self> {
		Some(Payload {
			identifiers: None,
			external_account_binding: None,
			contact: None,
			terms_of_service_agreed: Some(true),
		})
	}
	fn _new_acct_with_eab(email: String, body: SigBody) -> Option<Self> {
		Some(Payload {
			identifiers: None,
			terms_of_service_agreed: Some(true),
			external_account_binding: Some(body),
			contact: Some(vec![format!("mailto:{}", email)]),
		})
	}
	fn _new_order(dns: String) -> Option<Self> {
		let list: Vec<Identifier> = dns.split(",").map(|s| Identifier::new(s.to_string())).collect();
		Some(Payload {
			identifiers: Some(list),
			terms_of_service_agreed: None,
			external_account_binding: None,
			contact: None,
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
	pub fn from(payload: Option<Payload>, protected: Protected, file_path: &str) -> Self {
		Self::new(Self::payload64(payload), protected, file_path)
	}

	pub fn new(payload64: String, protected: Protected, file_path: &str) -> Self {
		let protected_json = serde_json::to_string(&protected).unwrap();
		let protected64 = _base64(protected_json.as_bytes());

		let plain = format!("{}.{}", protected64, payload64);

		let signature = if protected.alg.starts_with("H") {
			_base64_hmac256(file_path, &plain)
		} else {
			_sign_by_cmd_openssl(file_path, &plain, protected.alg.starts_with("E"), &protected.alg[2..])
		};
		SigBody {
			payload: payload64,
			protected: protected64,
			signature: signature,
		}
	}

	pub fn to_string(&self) -> Option<String> {
		Some(serde_json::to_string(&self).unwrap())
	}
	pub fn payload64(payload: Option<Payload>) -> String {
		match payload {
			Some(p) => {
				let payload_json = serde_json::to_string(&p).unwrap();
				//.replace("\":", "\": ");
				let payload64 = _base64(payload_json.as_bytes());
				//println!("payload:{:?}, => \n{}\npayload64:{}", p, payload_json, payload64);
				payload64
			}
			None => "".to_string(),
		}
	}
}

#[derive(Deserialize, Debug)]
struct OrderRes {
	identifier: Option<Identifier>,
	status: String,
	expires: String,
	authorizations: Option<Vec<String>>,
	challenges: Option<Vec<OrderResChall>>,
	finalize: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OrderResChall {
	#[serde(rename(deserialize = "type"))]
	_type: String,
	url: String,
	status: String,
	token: String,
}

// struct AcmeData {

// }
async fn _http_json(url: &str, body: Option<String>, method: Method) -> Result<reqwest::Response, AcmeError> {
	//let params: HashMap<&str, &str> = [("host", h), ("type", "auto")].into_iter().collect();
	println!("request {:?}: {}\nbody: {:?}", &method, url, &body);

	let client = reqwest::Client::new();

	let cb = match method {
		Method::GET => client.get(url),
		Method::HEAD => client.head(url),
		Method::POST_FORM => client.post(url),
		_ => client.post(url).body(body.unwrap()),
	};

	let response = cb
		.header("Content-Type", "application/jose+json")
		.header("User-Agent", "acme.rs")
		.send()
		.await
		.map_err(AcmeError::from)?;

	let c = response.status().as_u16();
	println!("response: {}, header: {:?}", c, response.headers());

	if !response.status().is_success() {
		println!("{}", response.text().await?);
		Err(AcmeError::Tip(format!("{}Error", c)))
	} else {
		Ok(response)
	}
}

// GET https://acme-v02.api.letsencrypt.org/directory
// curl https://acme-v02.api.letsencrypt.org/directory -ik
async fn _directory(url: String) -> Result<Directory, AcmeError> {
	let res = _http_json(&url, None, Method::GET).await?.text().await?;
	println!("Directory: {}", res);
	let dir: Directory = serde_json::from_str(&res).map_err(AcmeError::from)?;
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
	let res = _http_json(url, None, Method::HEAD).await?;
	Ok(_get_header(REPLAY_NONCE, res.headers()))
}

async fn _eab_email(url: &str, email: &str) -> Result<Eab, AcmeError> {
	let url = format!("{}?email={}", url, email);
	let res = _http_json(&url, None, Method::POST_FORM).await?.text().await?;
	println!("{}", &res);
	let eab: Eab = serde_json::from_str(&res).map_err(AcmeError::from)?;
	if !eab.success {
		return Err(AcmeError::Tip("Get Eab Fialed.".to_string()));
	}
	Ok(eab)
	//let eab_protected64 = SigBody::protected64(&Protected::from_eab(&url, "HS256", &eab.eab_kid));

	// eab_protected='{"alg":"HS256","kid":"gj62qW8CasolhDGQIcW0jQ","url":"https://acme.zerossl.com/v2/DV90/newAccount"}'
	// eab_payload64='eyJjcnYiOiAiUC0yNTYiLCAia3R5IjogIkVDIiwgIngiOiAiOGdOTllpaGg0UUVRNHFZTGZMLUtwTzltQWlwcVVUMWF2RS1QelBKb2trMCIsICJ5IjogIjhfWGh4cFBFcXJmaDd2S0hqZ2t3dmxKSmRRdzhIV0hGazY5THBjb3JqdHMifQ'

	//let eab_signature = _base64_hmac256(&eab.eab_hmac_key, &format!("{}.{}", eab_protected64, eab_payload64));
	//Ok((eab_protected64, eab_payload64))
}

async fn _new_acct(
	url: String,
	nonce: String,
	email: Option<String>,
	file_path: &str,
	alg: &str,
	jwk: Jwk,
) -> Result<(String, String), AcmeError> {
	//let payload_reg = "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6IHRydWV9"; //("termsOfServiceAgreed", true);
	// protected='{"nonce": "5yfKMBJJlBFlOD5krHoGQPfcIGi-ad7Ri5bfCjM2Hnys1Q8WBD8", "url": "https://acme-v02.api.letsencrypt.org/acme/new-acct", "alg": "ES256", "jwk": {"crv": "P-256", "kty": "EC", "x": "JP6zfy5Fey4_6jt6J3Tcq-d5dlK05_4r17OKtMTm6bc", "y": "rDQt-nR5riRjwhDVx5D2IoZZZ9YDyWOaqE2P4GaY0UA"}}'
	// let jwk_alg = _print_key_by_cmd_openssl(&file_path, is_ecc);

	let payload = if let Some(email) = email {
		let eab = _eab_email(&_URL_ZERO_EAB, &email).await?;
		let eab_payload64 = _base64(jwk.to_string().as_bytes());
		let sb = SigBody::new(
			eab_payload64,
			Protected::from_eab(&url, "HS256", &eab.eab_kid.unwrap()),
			&eab.eab_hmac_key.unwrap(),
		);
		let p = Payload::_new_acct_with_eab(email, sb);
		println!("with_eab: {:?}", p);
		p
	} else {
		Payload::_new_acct()
	};

	let protected = Protected::from(&url, nonce, alg, jwk);
	let sig_body = SigBody::from(payload, protected, file_path);

	let res = _http_json(&url, sig_body.to_string(), Method::POST).await?;
	let (nonce, location) = (
		_get_header(REPLAY_NONCE, res.headers()),
		_get_header("location", res.headers()),
	);

	Ok((nonce, location))
}

async fn _new_order(
	url: String,
	nonce: String,
	file_path: &str,
	alg: &str,
	kid: &str,
	dns: String,
) -> Result<(String, OrderRes), AcmeError> {
	let protected = Protected::from_kid(&url, nonce, alg, kid);
	let sig_body = SigBody::from(Payload::_new_order(dns), protected, file_path);

	let res = _http_json(&url, sig_body.to_string(), Method::POST).await?;
	let o = _get_header(REPLAY_NONCE, res.headers());
	let res_str = res.text().await?;
	let or_: OrderRes = serde_json::from_str(&res_str).unwrap();
	Ok((o, or_))
}

async fn _auth_domain(
	url: String,
	nonce: String,
	file_path: &str,
	alg: &str,
	kid: &str,
) -> Result<(String, OrderRes), AcmeError> {
	//protected='{"nonce": "I4RLVp83dJs_Cmdyr2DAkMP1a2UeHlIj0oYrOgQiG0B_T0YslvQ", "url": "https://acme-v02.api.letsencrypt.org/acme/authz-v3/366261494877", "alg": "ES256", "kid": "https://acme-v02.api.letsencrypt.org/acme/acct/1792176437"}'
	let protected = Protected::from_kid(&url, nonce, alg, kid);
	let sig_body = SigBody::from(Payload::_new_authz(), protected, file_path);

	let res = _http_json(&url, sig_body.to_string(), Method::POST).await?;
	let o = _get_header(REPLAY_NONCE, res.headers());
	let res_str = res.text().await?;
	let or_: OrderRes = serde_json::from_str(&res_str).unwrap();
	//}
	Ok((o, or_))
}

async fn _write_to_well_known(token: String, domain: &str, acme_dir: &str, thumbprint: &str) -> Result<(), AcmeError> {
	let token = token.replace(r"[^A-Za-z0-9_\-]", "_");
	let key_authorization = format!("{0}.{1}", token, thumbprint);
	let well_known_path = format!("{}/{}", acme_dir, token);
	let _ = File::create(&well_known_path)
		.map_err(|_e| AcmeError::Tip(format!("Create file failed: {}. {}", well_known_path, _e.to_string())))?
		.write(key_authorization.as_bytes())
		.map_err(|_| AcmeError::Tip(format!("Write failed: {}", well_known_path)));
	let wellknown_url = format!("http://{0}/.well-known/acme-challenge/{1}", domain, token);
	let ka = _http_json(&wellknown_url, None, Method::GET).await?.text().await?; // 自己先验一下
	if ka != key_authorization {
		return Err(AcmeError::Tip(format!("Check failed: {}", wellknown_url)));
	}
	Ok(())
}

async fn _chall_domain(
	url: String,
	nonce: String,
	file_path: &str,
	alg: &str,
	kid: &str,
) -> Result<(String, OrderResChall), AcmeError> {
	//protected='{"nonce": "I4RLVp830DhlbzGGoGqxd90G_wxxqbI25XFqmD1fxqaPMj4H_Os", "url": "https://acme-v02.api.letsencrypt.org/acme/chall-v3/366261494887/3xX-Gg", "alg": "ES256", "kid": "https://acme-v02.api.letsencrypt.org/acme/acct/1792176437"}'
	let protected = Protected::from_kid(&url, nonce, alg, kid);
	let sig_body = SigBody::from(Payload::_new_chall(), protected, file_path);

	let res = _http_json(&url, sig_body.to_string(), Method::POST).await?;
	let o = _get_header(REPLAY_NONCE, res.headers());
	let res_str = res.text().await?;

	let or_: OrderResChall = serde_json::from_str(&res_str).unwrap();
	if or_.status == STATUS_OK {
		println!("Successful.")
	}
	Ok((o, or_))
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
	println!("sha2 sha256 base64: {}", b64_hash);
	b64_hash
}

fn _gen_key_by_cmd_openssl(account_key_path: &str, alg: &Alg) -> Output {
	let a: Vec<&str> = match alg {
		Alg::RSA2 => vec!["genrsa", "-out", account_key_path, "2048"],
		Alg::RSA4 => vec!["genrsa", "-out", account_key_path, "4096"],
		Alg::ECC2 => vec!["ecparam", "-name", "prime256v1", "-genkey", "-out", account_key_path],
		Alg::ECC3 => vec!["ecparam", "-name", "secp384r1", "-genkey", "-out", account_key_path],
		Alg::ECC5 => vec!["ecparam", "-name", "secp521r1", "-genkey", "-out", account_key_path],
	};

	let out = Command::new("openssl").args(a).output().unwrap();
	out
}

fn _print_key_by_cmd_openssl(account_key_path: &str, is_ecc: bool) -> Jwk {
	let alg = if is_ecc { "ec" } else { "rsa" };
	let out = Command::new("openssl")
		.args([alg, "-in", account_key_path, "-noout", "-text"])
		.output()
		.unwrap();
	let out = String::from_utf8(out.stdout).unwrap();
	println!("out: \n{}", &out);

	Jwk::call(&out, is_ecc)
}

fn _sign_by_cmd_openssl(account_key_path: &str, plain: &str, is_ecc: bool, alg_len: &str) -> String {
	let sha = format!("-sha{}", &alg_len);
	//let rsa :&[&str]= &["dgst", &sha, "-sign", &file_path];
	//let ecc :&[&str]= &["dgst", &sha, "-sign", &file_path, "|", "openssl", "asn1parse", "-inform", "DER"];
	// echo "" | openssl dgst -sha256 -sign ~/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/account.key
	let mut child = Command::new("openssl")
		.args(&["dgst", &sha, "-sign", &account_key_path])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped()) // 捕获输出
		.spawn()
		.unwrap();

	{
		let stdin = child.stdin.as_mut().expect("Failed to open stdin");
		stdin.write_all(&plain.as_bytes()).unwrap()
	}

	// println!(
	// 	"echo \"{}\" | openssl dgst -sha256 -sign {} {} | openssl base64",
	// 	&plain,
	// 	&account_key_path,
	// 	if is_ecc { "| openssl asn1parse -inform DER" } else { "" }
	// );

	let out = child.wait_with_output().unwrap();
	if is_ecc {
		let mut child = Command::new("openssl")
			.args(&["asn1parse", "-inform", "DER"])
			.stdin(Stdio::piped())
			.stdout(Stdio::piped()) // 捕获输出
			.spawn()
			.unwrap();

		{
			let stdin = child.stdin.as_mut().expect("Failed to open stdin");
			stdin.write_all(&out.stdout).unwrap()
		}
		let out = child.wait_with_output().unwrap();
		let out = String::from_utf8(out.stdout).unwrap();
		println!("sign ecc out:\n{}", &out);

		_base64_hex(&_asn1_parse(&out))
	} else {
		let out = _base64(&out.stdout);
		println!("sign rsa out: {}", &out);
		out
	}
}

/*
	0:d=0  hl=2 l=  70 cons: SEQUENCE
	2:d=1  hl=2 l=  33 prim: INTEGER           :9A610C19E73BE8EC7E9BDD8E87B8263BFEA000AA37CFB30A893CD8BC2CA0A3F7
   37:d=1  hl=2 l=  33 prim: INTEGER           :CE3F47012A7EB61095338B38D95B18E7CDB2EEFFA2BA26E83B226B9C58370A21
*/
fn _asn1_parse(text: &str) -> String {
	let re = Regex::new(r"prim: INTEGER\s*:\s*(\w+)").unwrap();

	// 使用 re.captures_iter() 来迭代所有匹配项
	// for cap in re.captures_iter(text) {
	//     if let Some(hex_string) = cap.get(1) {
	//         println!("Found hex string: {}", hex_string.as_str());
	//     }
	// }

	// 假设第一行是 x，第二行是 y
	let ec_r = re.captures(text).unwrap().get(1).map_or("", |m| m.as_str());
	let ec_s = re
		.captures_iter(text)
		.nth(1)
		.and_then(|cap| cap.get(1))
		.map_or("", |m| m.as_str());

	println!("ec_r: {}\nec_s: {}", ec_r, ec_s);

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
