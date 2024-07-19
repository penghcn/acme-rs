use acme_rs::{simple_cron, AcmeCfg, AcmeLogger};
use log::{error, info, LevelFilter};

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
            //return; //中断
            std::process::exit(1);
        }
        Ok(cfg) => cfg,
    };

    log::set_max_level(cfg.log_level);

    if let Err(_e) = simple_cron(&cfg).await {
        error!("{}", _e.to_string());
        std::process::exit(2);
    }
}
