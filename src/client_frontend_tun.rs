#![allow(unused_must_use)]
use std::net;
use std::time;
use std::thread;
use std::process;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use std::os::unix::io::IntoRawFd;

use tun::Device;
use tun::configure;
use tun::platform::linux;

use crate::utils;
use crate::client;
use crate::encoder::Encoder;
use crate::encoder::EncoderMethods;

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str, 
            PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize, tun_ip: &str) {

    let mut conf = configure();
    conf.address(tun_ip);
    conf.netmask("255.255.255.0");
    conf.mtu((BUFFER_SIZE-60) as i32);

    let mut iface = linux::create(&conf).unwrap_or_else(|_err|{
        eprintln!("Failed to create tun device, {}", _err);
        process::exit(-1);
    });
    iface.enabled(true).unwrap();

    // special 'handshake' packet as the first packet
    let mut first_packet = vec![0x44];
    first_packet.append(&mut iface.address().unwrap().octets().to_vec());
    let first_packet:&'static [u8] = Box::leak(first_packet.into_boxed_slice());

    let tun_fd = iface.into_raw_fd();

    loop {  
        // we use loop here, to restart the connection on "decode error...."
        handle_tun_data(tun_fd, KEY, METHOD, SERVER_ADDR, PORT_START, PORT_END, BUFFER_SIZE, first_packet);
    }
}


fn handle_tun_data(tun_fd: i32, KEY:&'static str, METHOD:&'static EncoderMethods, 
                SERVER_ADDR:&'static str, PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize, 
                first_packet:&'static [u8]){

    struct Server {
        stream: net::TcpStream,
        encoder: Encoder,
    };
    let server = match client::tun_get_stream(KEY, METHOD, SERVER_ADDR, PORT_START, PORT_END, first_packet, 3){
        Some((stream, encoder)) => Server {stream, encoder},
        None => process::exit(-1),
    };
    let server = Arc::new(Mutex::new(server));
    let mut tun_reader = utils::tun_fd::TunFd::new(tun_fd);
    let mut tun_writer = utils::tun_fd::TunFd::new(tun_fd);

    let _server = server.clone();
    let _download = thread::spawn(move || {
        let mut index: usize = 0;
        let mut offset:i32;
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut stream_read = _server.lock().unwrap().stream.try_clone().unwrap();
        let mut decoder = _server.lock().unwrap().encoder.clone();
        loop {
            index += match stream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    //eprintln!("upstream read failed");
                    // try to restore connection, and without 'first_packet', retry forever
                    let server_new = match client::tun_get_stream(KEY, METHOD, SERVER_ADDR, PORT_START, PORT_END, first_packet, 0){
                        Some((stream, encoder)) => Server {stream, encoder},
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
                    match tun_writer.write(&buf[offset as usize- data_len .. offset as usize]) {
                        Ok(_) => (),
                        _ => {
                            //eprintln!("tun write failed");
                            stream_read.shutdown(net::Shutdown::Both);
                            break;
                        }
                    };
                    if (index - offset as usize) < (1 + 12 + 2 + 16) {
                        break;  // definitely not enough data to decode
                    }
                }
                else if _offset == -1 {
                     eprintln!("download stream decode error!");
                     offset = -1;
                     break;
                }
                else { break; } // decrypted_size ==0 && offset == 0: not enough data to decode
            }
            if offset == -1 {break;}    // TODO whether to exit ???
            buf.copy_within(offset as usize .. index, 0);
            index = index - (offset as usize);
        }
        println!("Download stream exited...");
    
    });

    let _server = server.clone();
    let _upload = thread::spawn(move || {
        let mut index: usize;
        let mut retry: usize;
        let mut buf = vec![0u8;  BUFFER_SIZE];
        let mut stream_write = _server.lock().unwrap().stream.try_clone().unwrap();
        let mut encoder = _server.lock().unwrap().encoder.clone();
        loop {
            index = match tun_reader.read(&mut buf[..BUFFER_SIZE-60]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    //eprintln!("tun read failed");
                    stream_write.shutdown(net::Shutdown::Both);
                    break;
                }
            };
            index = encoder.encode(&mut buf, index);
            loop 
            {
                retry = 0;
                match stream_write.write(&buf[..index]) {
                    Ok(_) => break,
                    _ => {
                        //eprintln!("upstream write failed");
                        // wait for the _download thread to restore the connection
                        // and will give up the data after 3 retry
                        stream_write = _server.lock().unwrap().stream.try_clone().unwrap();
                        encoder = _server.lock().unwrap().encoder.clone();
                        thread::sleep(time::Duration::from_millis((retry * 10) as u64));
                        retry += 1;
                        if retry > 3 {
                            break;
                        }
                    }
                }
            }
        }
        println!("Upload stream exited...");
    });

    _download.join();
    drop(_upload);  // drop the _upload thread to stop it, 
                    // cause it will always wait for _download thread to restore connection
}