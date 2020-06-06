#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::time;
use std::thread;
use std::process;
use std::io::prelude::*;
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::{mpsc, Arc, Mutex};

extern crate tun;
use crate::utils;
use tun::platform::posix;
use crate::encoder::{Encoder};
use std::net::{self, IpAddr, Ipv4Addr, TcpStream};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

#[cfg(target_os = "linux")]
const STRIP_HEADER_LEN: usize = 0;
#[cfg(target_os = "macos")]
const STRIP_HEADER_LEN: usize = 4;

pub fn setup(tun_addr: &str, MTU: usize) -> (posix::Reader, posix::Writer){
    let mut conf = tun::Configuration::default();
    let (addr, mask) = utils::parse_CIDR(tun_addr).unwrap_or_else(|_err|{
        error!("Failed to parse CIDR address: [{}]", tun_addr);
        process::exit(-1);
    });

    conf.address(addr)
        .netmask(mask)
        .mtu(MTU as i32)
        .up();

    let iface = tun::create(&conf).unwrap_or_else(|err|{
        error!("Failed to create tun device, {}", err);
        process::exit(-1);
    });

    iface.split()
}


//    pub fn handle_connection(&self, stream:net::TcpStream, encoder:Encoder) {
pub fn handle_connection(connection_rx: mpsc::Receiver<(TcpStream, Encoder)>, 
                        BUFFER_SIZE: usize, tun_ip: &str, MTU: usize){

    let clients: HashMap<Ipv4Addr, (TcpStream, Encoder)> = HashMap::new();
    let clients = Arc::new(Mutex::new(clients));
    let (mut tun_reader, tun_writer) = setup(tun_ip, MTU);
    #[cfg(target_os = "linux")]
    let mut route = utils::route::Route::new();

    let _clients = clients.clone();

    // thread: read from tun
    let _download = thread::spawn(move ||{
        let mut index: usize;
        let mut buf  = vec![0u8; BUFFER_SIZE];
        loop {
            index = match tun_reader.read(&mut buf) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => break
            };
            let dst_ip = Ipv4Addr::new(
                    buf[16 + STRIP_HEADER_LEN],
                    buf[17 + STRIP_HEADER_LEN],
                    buf[18 + STRIP_HEADER_LEN],
                    buf[19 + STRIP_HEADER_LEN]);

            if let Some((stream, encoder)) = _clients.lock().unwrap().get(&dst_ip) {
                index = encoder.encode(&mut buf[STRIP_HEADER_LEN..], index);
                // TODO need a better solution
                // fix1: use non-blocking or seperate threads for each client
                // fix2: try not to clone the stream each time.
                let mut stream_write = stream.try_clone().unwrap();
                match stream_write.write(&buf[STRIP_HEADER_LEN..index+STRIP_HEADER_LEN]) {
                    Ok(_) => continue,
                    Err(_) => continue,   // if client has disconnected, continue
                };
            }

            #[cfg(target_os = "linux")]     // lookup system route table, only for linux
            {
                if let Some(IpAddr::V4(next_hop)) = route.lookup(&dst_ip) {
                    if let Some((stream, encoder)) = _clients.lock().unwrap().get(&next_hop) {
                    index = encoder.encode(&mut buf[STRIP_HEADER_LEN..], index);
                    let mut stream_write = stream.try_clone().unwrap();
                    match stream_write.write(&buf[STRIP_HEADER_LEN..index+STRIP_HEADER_LEN]) {
                        Ok(_) => continue,
                        Err(_) => continue,   // if client has disconnected, continue
                    };
                    }
                }
            }
        }
        trace!("Download stream exited...");
    });


    let raw_fd: i32 = tun_writer.as_raw_fd();
    for (mut stream, encoder) in connection_rx {
        // thread: accept connection and write to channel
        let _clients = clients.clone();
        let mut _tun_writer = utils::tun_fd::TunFd::new(raw_fd);
        let _upload = thread::spawn(move || {
            stream.set_nodelay(true);
            stream.set_read_timeout(Some(time::Duration::from_secs(86400))).unwrap();   // timeout 24 hours
            let mut index: usize = 0;
            let mut offset:  i32 = 4 + 1 + 12 + 2 + 16;         // maximum data size read at first
            let mut last_offset: i32 = 0;

            let mut buf  = vec![0u8; BUFFER_SIZE];
            #[cfg(target_os = "macos")]
            let mut buf2 = vec![0u8; BUFFER_SIZE];
            let decoder = encoder.clone();
            let mut stream_read = stream.try_clone().unwrap();

            // get destination ip from first packet
            let src_ip: Ipv4Addr;
            loop {                                              // make sure read only one encrypted block
                index += match stream_read.read(&mut buf[index .. offset as usize]) {
                    Ok(read_size) if read_size > 0 => read_size,
                    _ => return,
                };

                let (data_len, _offset) = encoder.decode(&mut buf[..index]);
                offset = _offset;
                if data_len > 0 {
                    let data = &buf[offset as usize - data_len .. offset as usize];
                    match _tun_writer.write(data) {
                        Ok(_) => (),
                        Err(err) => error!("tun write failed, {}; data_len: {}, data: {:?}", err, data_len, data)
                    };

                    if data[0] == 0x44 {            // got special 'ipv4 handshake' packet
                        src_ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                        _clients.lock().unwrap().insert(src_ip, (stream_read, encoder));
                        break;
                    }
                    else if data[0] >> 4 == 0x4 {   // got an ipv4 packet, cool
                        src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                        _clients.lock().unwrap().insert(src_ip, (stream_read, encoder));
                        break;
                    }
                    else if data[0] == 0x66 {       // got special 'ipv6 handshake' packet
                        // TODO
                        continue;
                    }
                    else if data[0] >> 4 == 0x6 {   // got an ipv6 packet, have to do another round
                        index = 0;
                        offset = 1 + 12 + 2 + 16;
                        continue;
                    }
                }
                else if data_len ==0 && offset > 0 {        // left to be read
                    offset = index as i32 + offset;
                    continue;
                }
                else if offset == -1 {
                    error!("Conn Failed: [{}] <=> [{}], Client first packet error!",
                        stream.local_addr().unwrap(), stream.peer_addr().unwrap());
                }
                //stream.shutdown(net::Shutdown::Both);
                return;
            }

            info!("Conn OK: [{}] <=> [{}], with IP: [{}]", stream.local_addr().unwrap(), stream.peer_addr().unwrap(), src_ip);

            index = 0;
            loop {
                // from docs, size = 0 means EOF, 
                // maybe we don't need to worry about TCP Keepalive here.
                index += match stream.read(&mut buf[index..]) {
                    Ok(read_size) if read_size > 0 => read_size,
                    _ => break,
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
                            _tun_writer.write(&buf2[..data_len+4]).unwrap_or_else(|_err|{
                                error!("tun write failed, {}", _err);
                                0
                            });
                        }
                        #[cfg(target_os = "linux")]
                        {
                            _tun_writer.write(&buf[offset as usize - data_len .. offset as usize]).unwrap_or_else(|_err|{
                                error!("tun write failed, {}", _err);
                                0
                            });
                        }
                        if (index - offset as usize) < (1 + 12 + 2 + 16) {
                            break;              // definitely not enough data to decode
                        }
                    }
                    else if _offset == -1 {     // decrypted_size == 0 here
                        if last_offset == -1 {
                            offset = -2;
                        }
                        else {
                            offset = -1;
                        }
                        break;
                    }
                    else { break; }             // decrypted_size == 0 && offset != -1: not enough data to decode
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
                    error!("Packet decode error from: [{}]", stream.peer_addr().unwrap());
                    break;
                }
            }
            stream.shutdown(net::Shutdown::Both);
            trace!("Upload stream exited...");
        });
    }
}
