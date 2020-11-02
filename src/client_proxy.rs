#![allow(non_snake_case)]
#![allow(unused_must_use)]

use std::thread;
use std::error::Error;
use std::io::prelude::*;
use std::net::{self, SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr, TcpStream, TcpListener};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

use crate::client;
use crate::encoder::EncoderMethods;

/*
 * not using global Mutex for beter performance
 *
lazy_static::lazy_static! {
    pub static ref AUTH_USERNAME: Mutex<String> = Mutex::new(String::new());
    pub static ref AUTH_PASSWORD: Mutex<String> = Mutex::new(String::new());
}
*/

pub fn run(KEY: &'static str, METHOD: &'static EncoderMethods, SERVER_ADDR: &'static str,
    BIND_ADDR: &'static str, PORT_START: u32, PORT_END: u32, BUFFER_SIZE: usize, PROXY_AUTH: &'static str) {

    let listener = match TcpListener::bind(BIND_ADDR){
        Ok(listener) => listener,
        Err(err) => {
            error!("Failed to bind [{}], {}", BIND_ADDR, err);
            return;
        }
    };
    for stream in listener.incoming() {
        thread::spawn(move||{
            handle_connection(
                stream.unwrap(),
                KEY,
                METHOD,
                SERVER_ADDR,
                PROXY_AUTH,
                PORT_START,
                PORT_END,
                BUFFER_SIZE
            );
        });
    }
}

pub fn handle_connection(local_stream:  TcpStream,
                        KEY:            &'static str,
                        METHOD:         &'static EncoderMethods,
                        SERVER_ADDR:    &'static str,
                        PROXY_AUTH:     &'static str,
                        PORT_START:     u32,
                        PORT_END:       u32,
                        BUFFER_SIZE:    usize) {

    local_stream.set_nodelay(true);
    let mut local_stream_read = local_stream.try_clone().unwrap();
    let mut local_stream_write = local_stream.try_clone().unwrap();

    // do handshake before connecting to upstream
    let dest = match proxy_handshake(local_stream, PROXY_AUTH){
        Ok(dest) if dest.len() > 0 => dest,
        Ok(_) => return,
        Err(err) => {
            error!("handshake error: {}", err);
            return;
        }
    };

    let (upstream, encoder) = match client::get_stream(KEY, METHOD, 0, SERVER_ADDR, PORT_START, PORT_END) {
        Ok((upstream, encoder)) => (upstream, encoder),
        Err(err) => {
            error!("Error: Failed to connect to server, {}", err);
            return;
        }
    };

    upstream.set_nodelay(true);
    let mut upstream_read = upstream.try_clone().unwrap();
    let mut upstream_write = upstream.try_clone().unwrap();
    let decoder = encoder.clone();

    let mut buf = vec![0u8; BUFFER_SIZE];
    buf[ .. 9].copy_from_slice("TTCONNECT".as_bytes());
    buf[9 .. 9 + dest.len()].copy_from_slice(dest.as_bytes());
    let len = encoder.encode(&mut buf, 9 + dest.len());
    match upstream_write.write(&buf[..len]) {
        Ok(_) => (),
        _ => {
            error!("failed to write handshake message to upstream");
            return;
        }
    };

    // download stream
    let _download = thread::spawn(move || {
        //std::io::copy(&mut upstream_read, &mut local_stream_write);
        let mut index: usize = 0;
        let mut offset:  i32;
        let mut last_offset: i32 = 0;
        let mut buf = vec![0u8; BUFFER_SIZE];
        loop {
            index += match upstream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    //error!("upstream read failed");
                    break;
                }
            };
            offset = 0;
            loop {
                let (data_len, _offset) = decoder.decode(&mut buf[offset as usize..index]);
                if data_len > 0 {
                    offset += _offset;
                    match local_stream_write.write(&buf[offset as usize- data_len .. offset as usize]) {
                        Ok(_) => (),
                        _ => {
                            //error!("local_stream write failed");
                            offset = -2;
                            break;
                        }
                    };
                    if (index - offset as usize) < (1 + 12 + 2 + 16) {
                        break;  // definitely not enough data to decode
                    }
                }
                else if data_len == 0 && _offset == -1 {
                    if last_offset == -1 {
                        offset = -2;
                    }
                    else {
                        offset = -1;
                    }
                    break;
                }
                else { break; } // decrypted_size == 0 && offset != -1: not enough data to decode
            }

            if offset > 0 {
                buf.copy_within(offset as usize .. index, 0);
                index = index - (offset as usize);
                last_offset = 0;
            }
            else if offset == -1 {
                last_offset = -1;
            }
            else if offset == -2 {
                // if decryption failed continuously, then we kill the stream
                error!("Packet decode error!");
                break;
            }
        }
        upstream_read.shutdown(net::Shutdown::Both);
        local_stream_write.shutdown(net::Shutdown::Both);
        trace!("Download stream exited...");
    });

    // upload stream
    let _upload = thread::spawn(move || {
        //std::io::copy(&mut local_stream_read, &mut upstream_write);
        let mut index: usize;
        let mut buf = vec![0u8;  BUFFER_SIZE];
        loop {
            // from docs, size = 0 means EOF,
            // maybe we don't need to worry about TCP Keepalive here.
            index = match local_stream_read.read(&mut buf[..BUFFER_SIZE-60]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    //error!("local_stream read failed");
                    break;
                }
            };
            index = encoder.encode(&mut buf, index);
            match upstream_write.write(&buf[..index]) {
                Ok(_) => (),
                _ => {
                    //error!("upstream write failed");
                    break;
                }
            };
        }
        upstream_write.shutdown(net::Shutdown::Both);
        local_stream_read.shutdown(net::Shutdown::Both);
        trace!("Upload stream exited...");
    });
}


pub fn proxy_handshake(mut stream: TcpStream, PROXY_AUTH: &'static str) -> Result<String, Box<dyn Error>>{
    let mut buf = [0u8; 4096];
    let mut len = stream.peek(&mut buf)?;

    // SOCKS5
    if (len == 2 + buf[1] as usize) && buf[0]==0x05 {
        // for socks5, we consume the first packet
        stream.read(&mut buf)?;

        match PROXY_AUTH {
            // NO AUTH
            "<null>" => {
                stream.write(&[0x05, 0x00])?;
            },
            // USERNAME/PASSWORD
            _  => {
                let mut support_basic_auth = false;
                for i in 2 .. len {
                    if buf[i] == 0x02{
                        support_basic_auth = true;
                        break;
                    }
                }
                if !support_basic_auth {
                    stream.write(&[0x05, 0xFF])?;
                    return Err("SOCK5 AUTH Failed: client does not support USERNAME/PASSWORD basic auth".into());
                }
                stream.write(&[0x05, 0x02])?;
                len = stream.read(&mut buf)?;
                if len == 0 {
                    return Ok("".into())
                }
                let USERNAME = String::from_utf8_lossy(&buf[2 .. 2 + buf[1] as usize]);
                let PASSWORD = String::from_utf8_lossy(&buf[2 + buf[1] as usize + 1 .. len]);
                if PROXY_AUTH == format!("{}:{}", USERNAME, PASSWORD){
                    stream.write(&[0x01, 0x00])?;
                }
                else{
                    stream.write(&[0x01, 0x01])?;
                    return Err(format!("SOCKS5 AUTH Failed: username: [{}], password: [{}]", USERNAME, PASSWORD).into());
                }
            },
        };

        len = stream.read(&mut buf)?;
        if len == 0 {
            //return Err("Handshake failed at socks5: terminated".into());
            return Ok("".into())
        }
        match buf[1] {
            0x01 => (),     // CONNECT
            // 0x02 => (),     // BIND
            // 0x003 => (),    // UDP ASSOCIATE
            _ => return Err("Handshake failed at socks5: not CONNECT".into())
        }

        // do SOCKS5 CONNECT
        let port:u16 = ((buf[len-2] as u16) << 8) | buf[len-1] as u16;
        let domain = match buf[3] {
            0x01 => {                                   // ipv4 address
                    SocketAddr::from( SocketAddrV4::new(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]), port)).to_string()
            },
            0x03 => {                                   // domain name
                let length = buf[4] as usize;
                let mut domain = String::from_utf8_lossy(&buf[5..length+5]).to_string();
                domain.push_str(&":");
                domain.push_str(&port.to_string());
                domain
            },
            0x04 => {                                   // ipv6 address
                let buf = (2..10).map(|x| {
                    (u16::from(buf[(x * 2)]) << 8) | u16::from(buf[(x * 2) + 1])
                }).collect::<Vec<u16>>();

                SocketAddr::from( SocketAddrV6::new( Ipv6Addr::new(
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]), port, 0, 0)).to_string()
            },
            _ => return Err("Handshake failed at socks5: failed to parse address".into()),
        };

        debug!("[SOCKS5] CONNECT: {} => {}", stream.peer_addr().unwrap(), domain);
        buf[..10].copy_from_slice(&[0x5, 0x0, 0x0, 0x1, 0x7f, 0x0, 0x0, 0x1, 0x0, 0x0]);
        match stream.write(&buf[..10]) {
            Ok(_) => Ok(domain),
            Err(err) => Err(format!("Handshake failed at socks5: {}", err).into())
        }
    }

    // HTTP CONNECT
    else if &buf[0 .. 7] == "CONNECT".as_bytes() {
        // for HTTP CONNECT, we consume the first packet
        stream.read(&mut buf)?;
        let domain = String::from_utf8_lossy(&buf[..len]).split_whitespace().collect::<Vec<&str>>()[1].to_string();
        debug!("[HTTP] CONNECT: {} => {}", stream.peer_addr().unwrap(), domain);

        match stream.write("HTTP/1.0 200 Connection established\r\n\r\n".as_bytes()) {
            Ok(_) => Ok(domain.into()),
            Err(err) => Err(format!("Handshake failed at HTTP CONNECT: {}", err).into())
        }
    }

    // HTTP Plain
    else {
        // for HTTP Plain, we shall not consume the first packet
        // let domain = String::from_utf8_lossy(&buf[..len]).split_whitespace().collect::<Vec<&str>>()[1].to_string();
        let domain = String::from_utf8_lossy(&buf[..len]);
        let domain = domain.split_whitespace().collect::<Vec<&str>>();
        let domain = match domain.len() > 1 {
            true => domain[1],
            false => return Err("Handshake failed at HTTP Proxy, invalid request".into()),
        };
        debug!("[HTTP] Proxy: {} => {}", stream.peer_addr().unwrap(), domain);


        // let mut domain = domain.split("//").collect::<Vec<&str>>()[1].trim_end_matches('/').split("/").collect::<Vec<&str>>()[0].to_string();
        let domain = domain.split("//").collect::<Vec<&str>>();
        let mut domain = match domain.len() {
            1 => return Err("Handshake failed at HTTP Proxy, invalid request".into()),
            _ => domain[1].trim_end_matches('/').split("/").collect::<Vec<&str>>()[0].to_string(),
        };
        if !domain.contains(":") {
            domain.push_str(":80")
        }
        Ok(domain)
    }
}
