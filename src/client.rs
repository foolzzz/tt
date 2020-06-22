#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(unused_must_use)]

#[cfg(not(target_os = "windows"))]
extern crate socket2;

use std::time;
use std::thread;
use std::process;
use std::error::Error;
use std::io::prelude::*;
use std::net::{TcpStream, UdpSocket, SocketAddr, ToSocketAddrs};

use crate::utils;
use crate::encoder::{Encoder, EncoderMethods};
use crate::encoder::aes256gcm::AES256GCM;
use crate::encoder::chacha20poly1305::ChaCha20;

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

#[cfg(not(target_os = "windows"))]
use crate::client_tun;
use crate::client_proxy;

pub fn get_stream(KEY:&'static str, METHOD:&'static EncoderMethods, time_now:u64,
            SERVER_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32) 
                    -> Result<(TcpStream, Encoder), Box<dyn Error>> {
    
    let time_now = match time_now {
        0 => utils::get_secs_now() / 60,
        _ => time_now
    };
    let otp = utils::get_otp(KEY, time_now);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let server = format!("{}:{}", SERVER_ADDR, port);
    debug!("Using port: [{}]", port);
    let server:Vec<SocketAddr> = server.to_socket_addrs()?.collect();

    let encoder = match METHOD {
        EncoderMethods::AES256 => Encoder::AES256(AES256GCM::new(KEY, otp)),
        EncoderMethods::ChaCha20 => Encoder::ChaCha20(ChaCha20::new(KEY, otp)),
    };

    Ok(
        (   // if we want to use connect_timeout here, we can only use one server
            TcpStream::connect_timeout(&server[0], time::Duration::from_secs(5))?,
            encoder
        )
    )
}

#[cfg(not(target_os = "windows"))]
pub fn get_stream_new(KEY:&'static str, METHOD:&'static EncoderMethods, time_now:u64,
                        SERVER_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32,
                        first_packet:&'static [u8], is_udp: bool)
        -> Result<(socket2::Socket, Encoder), Box<dyn Error>> {

    let time_now = match time_now {
        0 => utils::get_secs_now() / 60,
        _ => time_now
    };
    let otp = utils::get_otp(KEY, time_now);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let server = format!("{}:{}", SERVER_ADDR, port);
    debug!("Using port: [{}]", port);
    let server:Vec<SocketAddr> = server.to_socket_addrs()?.collect();

    let encoder = match METHOD {
        EncoderMethods::AES256 => Encoder::AES256(AES256GCM::new(KEY, otp)),
        EncoderMethods::ChaCha20 => Encoder::ChaCha20(ChaCha20::new(KEY, otp)),
    };

    let mut sock = if is_udp {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(&server[0])?;

        // for udp, first write will never fail, but second read/write will fail if CONNECTION REFUSED
        // and cause the server will consume the first packet, we hence send some random data first.
        let mut random_bytes = utils::get_random_bytes().1;
        random_bytes.append(&mut utils::get_random_bytes().1);
        random_bytes.append(&mut utils::get_random_bytes().1);
        sock.send(&random_bytes)?;

        // sleep sometime to wait the OS see whether the dst port is accessilbe or not
        thread::sleep(time::Duration::from_millis(100));

        socket2::Socket::from(sock)
    }
    else{
        // if we want to use connect_timeout here, we can only use one server
        let sock = TcpStream::connect_timeout(&server[0], time::Duration::from_secs(5))?;
        socket2::Socket::from(sock)
    };

    let mut buf = vec![0u8;1024];
    let mut len = first_packet.len();
    if len > 0 {
        buf[..len].copy_from_slice(first_packet);
        len = encoder.encode(&mut buf, len);
        sock.write(&buf[..len])?;
    }

    Ok((sock, encoder))
}


#[cfg(not(target_os = "windows"))]
pub fn tun_get_stream(KEY:&'static str, METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str,
                PORT_START:u32, PORT_END:u32, first_packet:&'static [u8], retry_max: usize, is_udp: bool)
            -> Option<(socket2::Socket, Encoder)> {

    let mut retry:usize = 0;
    let mut sleep_secs: u64 = 0;
    loop {
//        match get_stream(KEY, METHOD, utils::get_secs_now() / 60 + 1, SERVER_ADDR, PORT_START, PORT_END) {
        match get_stream_new(KEY, METHOD, 0, SERVER_ADDR, PORT_START, PORT_END, first_packet, is_udp) {
            Ok((stream, encoder)) =>{
                stream.set_nodelay(true);
                return Some((stream, encoder));
            },
            Err(err) => {
                retry += 1;
                if retry <= retry_max && retry_max > 0{
                    sleep_secs = retry as u64;
                }
                else if retry <= 3 && retry_max == 0 {
                    sleep_secs = retry as u64;
                }
                else if retry > retry_max && retry_max == 0 {
                    sleep_secs = 15;
                }
                else if retry > retry_max && retry_max > 0{      // retry_max=0: keep retry forever
                    error!("Error: {}, Retry limits exceeds", err);
                    return None;
                }
                error!("Error: {}, Retry in {} seconds.", err, sleep_secs);
                thread::sleep(time::Duration::from_secs(sleep_secs));
                continue;
            }
        };
    };
}

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str, 
            LISTEN_ADDR:&'static str, PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize, 
            TUN_IP: Option<String>, TUN_PROTO: String, MTU: usize) {

    if let Some(tun_ip) = TUN_IP {
//        if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        {
            error!("Error: tun mode does not support windows for now");
            process::exit(-1);
        }

        #[cfg(not(target_os = "windows"))]
        {
            info!("TT {}, Client (tun mode on {})", env!("CARGO_PKG_VERSION"), TUN_PROTO.to_uppercase());
            client_tun::run(&KEY, METHOD, &SERVER_ADDR, PORT_START, PORT_END, BUFFER_SIZE, &tun_ip, &TUN_PROTO, MTU);
        }
    }
    else{
        info!("TT {}, Client (proxy mode)", env!("CARGO_PKG_VERSION"));
        client_proxy::run(&KEY, METHOD, &SERVER_ADDR, &LISTEN_ADDR, PORT_START, PORT_END, BUFFER_SIZE);
    }
}
