#![allow(unused_must_use)]
use std::net;
use std::env;
use std::time;
use std::thread;
use std::process;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::os::unix::io::{RawFd, IntoRawFd};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

extern crate tun;
use crate::utils;
use crate::client;
use crate::encoder::Encoder;
use crate::encoder::EncoderMethods;

#[cfg(target_os = "linux")]
const STRIP_HEADER_LEN: usize = 0;
#[cfg(target_os = "macos")]
const STRIP_HEADER_LEN: usize = 4;

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str, 
            PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize, tun_addr: &str, tun_proto: &str, MTU:usize) {

    let (addr, mask) = utils::parse_CIDR(tun_addr).unwrap_or_else(|_err|{
        error!("Failed to parse CIDR address: [{}]", tun_addr);
        process::exit(-1);
    });

    let tun_fd =
        if let Ok(value) = env::var("TT_TUN_FD"){
            value.parse::<RawFd>().unwrap()
        }
        else if let Ok(value) = env::var("TT_TUN_UDP_SOCKET_ADDR"){
            debug!("TT_TUN_UDP_SOCKET_ADDR:{}", value);
            process::exit(-1);
        }
        else if let Ok(value) = env::var("TT_TUN_UNIX_SOCKET_PATH") {
            utils::unix_seqpacket::connect(&value).unwrap_or_else(||{
                error!("Failed to connect to:{}", &value);
                process::exit(-1);
            })
        }
        else {
            let mut conf = tun::Configuration::default();
            conf.address(addr)
                .netmask(mask)
                .mtu(MTU as i32)
                .up();

            let iface = tun::create(&conf).unwrap_or_else(|_err|{
                error!("Failed to create tun device, {}", _err);
                process::exit(-1);
            });
            iface.into_raw_fd()
        };

    // special 'handshake' packet as the first packet
    let mut first_packet = vec![0x44];
    first_packet.append(&mut addr.octets().to_vec());
    first_packet.append(&mut utils::get_random_bytes().1);
    first_packet.append(&mut utils::get_random_bytes().1);
    let first_packet:&'static [u8] = Box::leak(first_packet.into_boxed_slice());

    let is_udp = if tun_proto.to_uppercase() == "TCP" { false } else { true };
    loop {  
        // we use loop here, to restart the connection on "decode error...."
        handle_tun_data(tun_fd, KEY, METHOD, SERVER_ADDR, PORT_START, PORT_END, BUFFER_SIZE, first_packet, is_udp);
    }
}


fn handle_tun_data(tun_fd: i32, KEY:&'static str, METHOD:&'static EncoderMethods, 
                SERVER_ADDR:&'static str, PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize, 
                first_packet:&'static [u8], is_udp: bool){

    struct Server {
        stream:     socket2::Socket,
        encoder:    Encoder,
        renewed:    bool,
    };
    let server = match client::tun_get_stream(KEY, METHOD, SERVER_ADDR, PORT_START, PORT_END, first_packet, 3, is_udp){
        Some((stream, encoder)) => Server {stream, encoder, renewed: false},
        None => process::exit(-1),
    };

    let server = Arc::new(Mutex::new(server));
    let mut tun_reader = utils::tun_fd::TunFd::new(tun_fd);
    let mut tun_writer = utils::tun_fd::TunFd::new(tun_fd);

    let _server = server.clone();
    let _download = thread::spawn(move || {
        let mut index: usize = 0;
        let mut offset:  i32;
        let mut last_offset: i32 = 0;

        let mut buf = vec![0u8; BUFFER_SIZE];
        #[cfg(target_os = "macos")]
        let mut buf2 = vec![0u8; BUFFER_SIZE];
        let mut stream_read = _server.lock().unwrap().stream.try_clone().unwrap();
        let mut decoder = _server.lock().unwrap().encoder.clone();
        loop {
            index += match stream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    index = 0;      // clear the buf

                    // call shutdown, make sure the 'write()' to fail on UDP socket
                    stream_read.shutdown(net::Shutdown::Both);

                    // error!("upstream read failed");
                    // try to restore connection, and without 'first_packet', retry forever
                    let server_new = match client::tun_get_stream(KEY, METHOD, SERVER_ADDR, PORT_START, PORT_END, first_packet, 0, is_udp){
                        Some((stream, encoder)) => Server {stream, encoder, renewed: true},
                        None => continue
                    };
                    stream_read = server_new.stream.try_clone().unwrap();
                    decoder = server_new.encoder.clone();
                    *_server.lock().unwrap() = server_new;
                    continue;
                }
            };
            offset = 0;
            loop {
                let (data_len, _offset) = decoder.decode(&mut buf[offset as usize..index]);
                if data_len > 0 {
                    offset += _offset;
                    #[cfg(target_os = "macos")]
                    {
                        buf2[..4].copy_from_slice(&[0,0,0,2]);
                        buf2[4..data_len+4].copy_from_slice(&buf[offset as usize- data_len .. offset as usize]);
                        tun_writer.write(&buf2[..data_len+4]).unwrap_or_else(|_err|{
                            error!("tun write failed, {}", _err);
                            0
                        });
                    }
                    #[cfg(target_os = "linux")]
                    {
                        tun_writer.write(&buf[offset as usize- data_len .. offset as usize]).unwrap_or_else(|_err|{
                            error!("tun write failed, {}", _err);
                            0
                        });
                    }
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
        stream_read.shutdown(net::Shutdown::Both);
        trace!("Download stream exited...");
    
    });

    let _server = server.clone();
    let _upload = thread::spawn(move || {
        let mut index: usize;
        let mut buf = vec![0u8;  BUFFER_SIZE];
        let mut buf2 = vec![0u8;  BUFFER_SIZE];
        let mut stream_write = _server.lock().unwrap().stream.try_clone().unwrap();
        stream_write.set_write_timeout(Some(std::time::Duration::from_secs(1)));
        let mut encoder = _server.lock().unwrap().encoder.clone();
        loop {
            index = match tun_reader.read(&mut buf) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    error!("tun read failed");
                    stream_write.shutdown(net::Shutdown::Both); // suicide here
                    break;
                }
            };
//            info!("going to write,  {} <==> {}",
//                stream_write.local_addr().unwrap().as_inet().unwrap(),
//                stream_write.peer_addr().unwrap().as_inet().unwrap()
//                );

            // outer loop: 2 times
            for _ in 0..2 {
                // move encode procedure inside the loop, cause the key bytes will change as the encoder
                buf2[..index].copy_from_slice(&buf[STRIP_HEADER_LEN..index+STRIP_HEADER_LEN]);
                let index2 = encoder.encode(&mut buf2, index);
                match stream_write.write(&buf2[..index2]) {
                    Ok(_) => break,
                    Err(e) => {
                        // error code 11: Resource temporarily unavailable
                        // the buffer may be full filled as a result of network failure, lost of FIN, etc..
                        // (need to set write timeout)
                        if e.raw_os_error().unwrap() == 11 {
                            error!("upstream write failed, {:?}", e);
                        }
                        else{
                            // error!("upstream write failed, {:?}", e);
                        }
                        stream_write.shutdown(net::Shutdown::Both); // force the download thread to reconnect

                        // for tcp, we may retry after some seconds (total 1320ms),
                        //          no matter whether we got a new connection or not;
                        //
                        // for udp, we may wait forever (about 1h actually), make sure the client
                        //          will not send packet to the "old failed" socket on another run.
                        //
                        //      However, this is not enough when the server stops and restarts immediately.
                        //      1) The 'read()' fails and then reconnects, so Server got this new
                        //         connection. but the 'writer' thread does not know the failure,
                        //         if the newly started server still got the "old" port on, the
                        //         'writer' thread will sends packets using the old socket.
                        //         Been fixed it by shutdown() the socket once read() failed.
                        //         (see line: 113)
                        //
                        let retry_max = if is_udp { 3600 } else { 12 };
                        for mut retry in 0..retry_max{
                            if retry > 50 { retry = 50 }    // it will not affect the loop times
                            //error!("upstream write failed, {:?}", e);
                            thread::sleep(time::Duration::from_millis(retry * 20));
                            let renewed = _server.lock().unwrap().renewed;

                            // check 'renewed' here to avoid client trying to send stupid packet at UDP mode
                            if renewed{
                                encoder = _server.lock().unwrap().encoder.clone();
                                stream_write = _server.lock().unwrap().stream.try_clone().unwrap();
                                stream_write.set_write_timeout(Some(std::time::Duration::from_secs(1)));
                                _server.lock().unwrap().renewed = false;
                                break
                            }
                        }
                    }
                }
            }
        }
        trace!("Upload stream exited...");
    });

    _download.join();
    drop(_upload);  // drop the _upload thread to stop it, 
                    // cause it will always wait for _download thread to restore connection
}
