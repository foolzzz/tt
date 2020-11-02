#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
extern crate log;
extern crate structopt;

use std::process;
use structopt::StructOpt;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

mod utils;
mod server;
mod client;
mod encoder;
#[cfg(not(any(target_os = "windows", target_os = "android")))]
mod server_tun;
#[cfg(not(target_os = "windows"))]
mod client_tun;
mod server_proxy;
mod client_proxy;

use encoder::EncoderMethods;

#[derive(StructOpt, Debug)]
#[structopt(name = "TT", about = "TT, The Tunnel")]
enum Opt {
    #[structopt(name = "server", about = "TT, The Tunnel, server side")]
    server {
        #[structopt(short = "l", long = "listen", default_value = "0.0.0.0")]
        LISTEN_ADDR: String,
        #[structopt(short = "k", long = "key")]
        KEY: String,
        #[structopt(short, long, default_value = "chacha20-poly1305")]
        METHODS: String,
        #[structopt(short, long = "port-range", default_value = "1024-65535")]
        RANGE: String,

        // max_tt_header = 1 + range(12, 33) + 16 = 49
        // for UDP: MTU <= 1500 - 20 - 8 - max_tt_header = 1423
        // for TCP: MTU <= 1500 - 20 - 20 - max_tt_header = 1411
        #[structopt(long, default_value = "1410")]
        TUN_MTU: usize,
        #[structopt(long)]
        TUN_IP: Option<String>,
        #[structopt(long, default_value = "UDP")]
        TUN_PROTO: String,
        #[structopt(long="no-port-jump-on-tun-mode")]
        NO_PORT_JUMP: bool,
        #[structopt(long="with-proxy")]
        WITH_PROXY: bool,
        #[structopt(short, long, parse(from_occurrences))]
        VERBOSE: u8,
        #[structopt(short, long)]
        QUIET: bool
    },

    #[structopt(name = "client", about = "TT, The Tunnel, client side")]
    client {
        #[structopt(short, long)]
        SERVER: String,
        #[structopt(short = "l", long = "listen", default_value = "127.0.0.1:1080")]
        LISTEN_ADDR: String,
        #[structopt(short = "k", long = "key")]
        KEY: String,
        #[structopt(short, long, default_value = "chacha20-poly1305")]
        METHODS: String,
        #[structopt(short, long = "port-range", default_value = "1024-65535")]
        RANGE: String,
        #[structopt(long, default_value = "1410")]
        TUN_MTU: usize,
        #[structopt(long, conflicts_with = "listen-addr")]
        TUN_IP: Option<String>,
        #[structopt(long, default_value = "UDP")]
        TUN_PROTO: String,
        #[structopt(long, default_value = "<null>")]
        PROXY_AUTH: String,
        #[structopt(short, long, parse(from_occurrences))]
        VERBOSE: u8,
        #[structopt(short, long)]
        QUIET: bool
    }
}

fn main() {
    utils::my_log::init_with_level(Level::Trace).unwrap();
    match Opt::from_args() {
        Opt::server{ LISTEN_ADDR, KEY, METHODS, RANGE, TUN_MTU, TUN_IP, TUN_PROTO, NO_PORT_JUMP, WITH_PROXY, VERBOSE, QUIET } => {
            set_verbose(VERBOSE, QUIET);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let BUFFER_SIZE = if TUN_MTU > (4096 - 60) { TUN_MTU + 60 } else { 4096 };
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let LISTEN_ADDR:&'static str = Box::leak(LISTEN_ADDR.into_boxed_str());
            let METHODS = match METHODS.as_ref() {
                "aes-256-gcm" => &EncoderMethods::AES256,
                "chacha20-poly1305" => &EncoderMethods::ChaCha20,
                _ => {
                    error!("Methods [{}] not supported!", METHODS);
                    process::exit(-1);
                }
            };
            assert!(TUN_MTU<=65536);
            assert!(PORT_RANGE_START <= PORT_RANGE_END);
            server::run(KEY, METHODS, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP, TUN_PROTO, TUN_MTU, NO_PORT_JUMP, WITH_PROXY);
        },
        Opt::client{ SERVER, LISTEN_ADDR, KEY, METHODS, RANGE, TUN_MTU, TUN_IP, TUN_PROTO, PROXY_AUTH, VERBOSE , QUIET } => {
            set_verbose(VERBOSE, QUIET);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let BUFFER_SIZE = if TUN_MTU > (4096 - 60) { TUN_MTU + 60 } else { 4096 };
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let SERVER_ADDR:&'static str = Box::leak(SERVER.into_boxed_str());
            let LISTEN_ADDR:&'static str = Box::leak(LISTEN_ADDR.into_boxed_str());
            let PROXY_AUTH:&'static str = Box::leak(PROXY_AUTH.into_boxed_str());
            let METHODS = match METHODS.as_ref() {
                "aes-256-gcm" => &EncoderMethods::AES256,
                "chacha20-poly1305" => &EncoderMethods::ChaCha20,
                _ => {
                    error!("Methods [{}] not supported!", METHODS);
                    process::exit(-1);
                }
            };
            assert!(TUN_MTU<=65536);
            assert!(PORT_RANGE_START <= PORT_RANGE_END);
            client::run(KEY, METHODS, SERVER_ADDR, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP, TUN_PROTO, TUN_MTU, PROXY_AUTH);
        },
    }
}

fn set_verbose(VERBOSE: u8, QUIET: bool) {
    // default to INFO
    if QUIET {
        log::set_max_level(Level::Warn.to_level_filter());
    }
    else{
        match VERBOSE {
            0 => log::set_max_level(Level::Info.to_level_filter()),
            1 => log::set_max_level(Level::Debug.to_level_filter()),
            _ => log::set_max_level(Level::Trace.to_level_filter()),
        }
    };
/*
    error!("error log");
    warn!("warn log");
    info!("info log");
    debug!("debug log");
    trace!("trace log");
*/
}
