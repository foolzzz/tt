extern crate log;
extern crate colored;
use colored::*;

use crate::utils;
use log::{Log, Level,Metadata,Record,SetLoggerError};

struct SimpleLogger{
    level: Level
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_str = record.level().to_string();
            #[cfg(not(target_os = "windows"))]
            let level_str = {
                match record.level() {
                    Level::Error => level_str.red(),
                    Level::Warn  => level_str.yellow(),
                    Level::Info  => level_str.white(),
                    Level::Debug => level_str.purple(),
                    Level::Trace => level_str.normal(),
                }
            };
            let target = if record.target().len() > 0 {
                record.target()
            } else {
                record.module_path().unwrap_or_default()
            };

            // for crate time-0.2, but it does not resolve the timezone problem with openwrt,
            // which has /etc/TZ instead of /etc/localtime, it doesn't work even with env TZ.
            //
            // let time_local = time::OffsetDateTime::now_local();
            // let time_str = format!("{} {}", time_local.date().format("%Y%m%d"), time_local.time().format("%T"));
            //
            // for crate time-0.1:
            // time::now().strftime("%Y%m%d %T").unwrap().to_string(),

            println!("{} [{:<5}] [{}] {}",
                utils::local_time("%Y%m%d %T", None).unwrap(),
                level_str,
                target,
                record.args());
        }
    }

    fn flush(&self) {
    }
}

pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
    check_TZ();
    log::set_boxed_logger(Box::new(SimpleLogger{ level }))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

#[allow(dead_code)]
pub fn init() -> Result<(), SetLoggerError> {
    init_with_level(Level::Trace)
}

// When building musl for some targets, the rustc will use it's own musl C lib,
// which does not work with some OS like openwrt. we do some work here.
pub fn check_TZ() {
    match std::env::var("TZ"){
        Ok(_) => (),
        Err(_) => {
            let path = std::path::Path::new("/etc/TZ");
            if path.exists() {
                let TZ = std::fs::read_to_string(path).unwrap_or_else(|err|{
                    eprintln!("Failed to read /etc/TZ, {}", err);
                    std::process::exit(-1);
                });
                std::env::set_var("TZ", TZ)
            }
        }
    }
}
