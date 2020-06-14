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
#[cfg(not(target_os = "windows"))]
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
        #[structopt(long, default_value = "1440")]
        TUN_MTU: usize,
        #[structopt(long)]
        TUN_IP: Option<String>,
        #[structopt(long, default_value = "UDP")]
        TUN_PROTO: String,
        #[structopt(long="no-port-jump-on-tun-mode")]
        NO_PORT_JUMP: bool,
        #[structopt(long="with-proxy")]
        WITH_PROXY: bool,
        #[structopt(short, long)]
        VERBOSE: bool,
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
        #[structopt(long, default_value = "1440")]
        TUN_MTU: usize,
        #[structopt(long, conflicts_with = "listen-addr")]
        TUN_IP: Option<String>,
        #[structopt(long, default_value = "UDP")]
        TUN_PROTO: String,
        #[structopt(short, long)]
        VERBOSE: bool,
    }
}

fn main() {
    utils::my_log::init_with_level(Level::Debug).unwrap();
    match Opt::from_args() {
        Opt::server{ LISTEN_ADDR, KEY, METHODS, RANGE, TUN_MTU, TUN_IP, TUN_PROTO, NO_PORT_JUMP, WITH_PROXY, VERBOSE } => {
            set_verbose(VERBOSE);
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
        Opt::client{ SERVER, LISTEN_ADDR, KEY, METHODS, RANGE, TUN_MTU, TUN_IP, TUN_PROTO, VERBOSE } => {
            set_verbose(VERBOSE);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let BUFFER_SIZE = if TUN_MTU > (4096 - 60) { TUN_MTU + 60 } else { 4096 };
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let SERVER_ADDR:&'static str = Box::leak(SERVER.into_boxed_str());
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
            client::run(KEY, METHODS, SERVER_ADDR, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP, TUN_PROTO, TUN_MTU);
        },
    }
}

fn set_verbose(VERBOSE :bool) {
    if !VERBOSE {
        log::set_max_level(Level::Info.to_level_filter());
    }
//    debug!("verbose output: on");
}
