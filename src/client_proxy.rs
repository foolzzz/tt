#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::net;
use std::thread;
use crate::client;
use std::io::prelude::*;
use crate::encoder::EncoderMethods;

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str, 
    BIND_ADDR:&'static str, PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize) {

    let listener = match net::TcpListener::bind(BIND_ADDR){
        Ok(listener) => listener,
        Err(err) => {
            error!("Failed to bind [{}], {}", BIND_ADDR, err);
            return;
        }
    };
    for stream in listener.incoming() {
        thread::spawn(move||{
            handle_connection(stream.unwrap(),
                KEY, METHOD, SERVER_ADDR, 
                PORT_START, PORT_END, BUFFER_SIZE);
        });
    }
}

pub fn handle_connection(local_stream:net::TcpStream, KEY:&'static str, 
                        METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str, 
                        PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize,) {
    let (upstream, encoder) = match client::get_stream(KEY, METHOD, 0, SERVER_ADDR, PORT_START, PORT_END) {
        Ok((upstream, encoder)) => (upstream, encoder),
        Err(err) => {
            error!("Error: Failed to connect to server, {}", err);
            return;
        }
    };
    local_stream.set_nodelay(true);
    upstream.set_nodelay(true);

    let mut upstream_read = upstream.try_clone().unwrap();
    let mut upstream_write = upstream.try_clone().unwrap();
    let mut local_stream_read = local_stream.try_clone().unwrap();
    let mut local_stream_write = local_stream.try_clone().unwrap();
    let decoder = encoder.clone();

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
