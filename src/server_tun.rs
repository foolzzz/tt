#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::time;
use std::thread;
use std::process;
use std::io::prelude::*;
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::os::unix::io::{RawFd, IntoRawFd};

extern crate tun;
extern crate socket2;

use crate::utils;
use crate::encoder::Encoder;
use std::net::{self, IpAddr, Ipv4Addr};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

#[cfg(target_os = "linux")]
const STRIP_HEADER_LEN: usize = 0;
#[cfg(target_os = "macos")]
const STRIP_HEADER_LEN: usize = 4;

pub fn setup(tun_addr: &str, MTU: usize) -> RawFd {
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

    iface.into_raw_fd()
}


pub fn handle_connection(connection_rx: mpsc::Receiver<(socket2::Socket, Encoder)>,
                        BUFFER_SIZE: usize, tun_ip: &str, tun_mode: u8, MTU: usize){
    let tun_fd = setup(tun_ip, MTU);
    if tun_mode == 1 {
        handle_connection_tcp(connection_rx, tun_fd, BUFFER_SIZE)
    }
    else{
        handle_connection_udp(connection_rx, tun_fd, BUFFER_SIZE)
    }
}


pub fn handle_connection_tcp(connection_rx: mpsc::Receiver<(socket2::Socket, Encoder)>,
                            tun_fd: RawFd, BUFFER_SIZE: usize){
    #[cfg(target_os = "linux")]
    let mut route = utils::route::Route::new();

    let clients: HashMap<Ipv4Addr, (socket2::Socket, Encoder)> = HashMap::new();
    let clients = Arc::new(Mutex::new(clients));
    let _clients = clients.clone();

    let mut tun_reader = utils::tun_fd::TunFd::new(tun_fd);

    // thread: read from tun
    let _upload = thread::spawn(move ||{
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
        trace!("{:?}, Upload stream exited...", thread::current().id());
    });


    for (mut stream, encoder) in connection_rx {
        // thread: accept connection and write to channel
        let _clients = clients.clone();
        let mut _tun_writer = utils::tun_fd::TunFd::new(tun_fd);
        let _download = thread::spawn(move || {
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
                            stream.local_addr().unwrap().as_inet().unwrap(),
                            stream.peer_addr().unwrap().as_inet().unwrap()
                    );
                }
                //stream.shutdown(net::Shutdown::Both);
                return;
            }

            info!("Conn OK: [{}] <=> [{}], with IP: [{}]",
                stream.local_addr().unwrap().as_inet().unwrap(),
                stream.peer_addr().unwrap().as_inet().unwrap(),
                src_ip
            );

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
                    error!("Packet decode error from: [{}]",
                        stream.peer_addr().unwrap().as_inet().unwrap()
                    );
                    break;
                }
            }
            stream.shutdown(net::Shutdown::Both);
            trace!("{:?}, Download stream exited...", thread::current().id());
        });
    }
}


pub fn handle_connection_udp(connection_rx: mpsc::Receiver<(socket2::Socket, Encoder)>,
                            tun_fd: RawFd, BUFFER_SIZE: usize){
    #[cfg(target_os = "linux")]
    let mut route = utils::route::Route::new();

    let clients: HashMap<Ipv4Addr, (socket2::Socket, Encoder)> = HashMap::new();
    let clients = Arc::new(Mutex::new(clients));
    let _clients = clients.clone();

    let mut tun_reader = utils::tun_fd::TunFd::new(tun_fd);

    // thread: read from tun
    let _upload = thread::spawn(move ||{
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

            let mut _clients_locked = _clients.lock().unwrap();
            let dest = if let Some((stream, encoder)) = _clients_locked.get(&dst_ip) {
                    Some((stream, encoder))
            }
            else{
                // lookup system route table, only for linux
                #[cfg(not(target_os = "linux"))]
                { None }
                #[cfg(target_os = "linux")]
                {
                    if let Some(IpAddr::V4(next_hop)) = route.lookup(&dst_ip) {
                        if let Some((stream, encoder)) = _clients_locked.get(&next_hop) {
                            Some((stream, encoder))
                        }
                        else { None }
                    }
                    else { None }
                }
            };

            if let Some((stream, encoder)) = dest{
                index = encoder.encode(&mut buf[STRIP_HEADER_LEN..], index);
                // TODO need a better solution, use UDP send_to() ?
                // fix1: use non-blocking or seperate threads for each client
                // fix2: try not to clone the stream each time.
                let mut stream_write = stream.try_clone().expect("failed to clone stream_write");
                match stream_write.write(&buf[STRIP_HEADER_LEN..index+STRIP_HEADER_LEN]) {
                    Ok(_) => (),
                    Err(_) => {
/*
                        // client disconnected or port lifetime expired
                        // we have to drop every ref to remove the socket
                        drop(stream);
                        drop(stream_write);
                        info!("{:?}, write error, remove the old socket", thread::current().id());
                        _clients_locked.remove(&dst_ip).unwrap();
*/
                    },
                };
            }
            drop(_clients_locked)
        }
        trace!("{:?}, Upload stream exited...", thread::current().id());
    });


    for (mut stream, encoder) in connection_rx {
        // thread: accept connection and write to channel
        let _clients = clients.clone();
        let mut _tun_writer = utils::tun_fd::TunFd::new(tun_fd);
        let _download = thread::spawn(move || {
            stream.set_nodelay(true);
            stream.set_read_timeout(Some(time::Duration::from_secs(86400))).unwrap();   // timeout 24 hours
            let mut index: usize;
            let mut failure_count: i32 = 0;

            let mut buf  = vec![0u8; BUFFER_SIZE];
            #[cfg(target_os = "macos")]
            let mut buf2 = vec![0u8; BUFFER_SIZE];
            let decoder = encoder.clone();
            let mut stream_read = stream.try_clone().unwrap();

            // get destination ip from first packet
            let src_ip: Ipv4Addr;
            loop {                                              // make sure read only one encrypted block
                index = match stream_read.read(&mut buf) {
                    Ok(read_size) if read_size > 1 => read_size,//make sure len >= 2, otherwise decode() may panic
                    _ => return,
                };

                let (data_len, offset) = encoder.decode(&mut buf[..index]);
                if data_len > 0 {
                    let data = &buf[offset as usize - data_len .. offset as usize];
                    match _tun_writer.write(data) {
                        Ok(_) => (),
                        Err(err) => error!("tun write failed, {}; data_len: {}, data: {:?}", err, data_len, data)
                    };

                    if data[0] == 0x44 {            // got special 'ipv4 handshake' packet
                        src_ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                        if let Some((old_stream, _)) = _clients.lock().unwrap().insert(src_ip, (stream_read, encoder)){
                            // make sure we kill the old stream to make the old thread exit
                            old_stream.shutdown(net::Shutdown::Both);
                        }
                        break;
                    }
                    else if data[0] >> 4 == 0x4 {   // got an ipv4 packet, cool
                        src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                        if let Some((old_stream, _)) = _clients.lock().unwrap().insert(src_ip, (stream_read, encoder)){
                            // make sure we kill the old stream to make the old thread exit
                            old_stream.shutdown(net::Shutdown::Both);
                        }
                        break;
                    }
                    else if data[0] == 0x66 {       // got special 'ipv6 handshake' packet
                        // TODO
                        continue;
                    }
                    else if data[0] >> 4 == 0x6 {   // got an ipv6 packet, have to do another round
                        // TODO
                        continue;
                    }
                }
                else if offset == -1 || data_len == 0 && offset > 0 {   // decode error, or left to be read, which shall not happen with UDP
                    error!("Conn Failed: [{}] <=> [{}], Client first packet error!",
                            stream.local_addr().unwrap().as_inet().unwrap(),
                            stream.peer_addr().unwrap().as_inet().unwrap()
                    );
                }
                //stream.shutdown(net::Shutdown::Both);
                return;
            }

            info!("Conn OK: [{}] <=> [{}], with IP: [{}]",
                stream.local_addr().unwrap().as_inet().unwrap(),
                stream.peer_addr().unwrap().as_inet().unwrap(),
                src_ip
            );

            loop {
                index = match stream.read(&mut buf) {
                    Ok(read_size) if read_size > 1 => read_size,
                    _ => break,
                };

                let (data_len, offset) = decoder.decode(&mut buf[..index]);
                if data_len > 0 {
                    #[cfg(target_os = "macos")]
                    {
                        buf2[..4].copy_from_slice(&[0,0,0,2]);
                        buf2[4..data_len+4].copy_from_slice(&buf[offset as usize - data_len .. offset as usize]);
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
                    failure_count = 0
                }
                else if offset == -1 {
                    failure_count += 1
                }

                if failure_count >= 2 {
                    // if decryption failed continuously, then we kill the stream
                    error!("Packet decode error from: [{}]", stream.peer_addr().unwrap().as_inet().unwrap());
                    break;
                }
            }
            stream.shutdown(net::Shutdown::Both);

            // client disconnected or port lifetime expired
            // we have to drop every ref to remove the socket
            let mut _clients_locked = _clients.lock().unwrap();
            if let Some((old_stream, _)) = _clients_locked.get(&src_ip){
                if stream.local_addr().unwrap().as_inet().unwrap() == old_stream.local_addr().unwrap().as_inet().unwrap()
                    && stream.peer_addr().unwrap().as_inet().unwrap() == old_stream.peer_addr().unwrap().as_inet().unwrap() {
                    //debug!("{:?}, read error, remove the old socket", thread::current().id());
                    _clients_locked.remove(&src_ip);
                }
                else{
                    //debug!("{:?}, read error, old socket already gone", thread::current().id());
                }
            }
            drop(stream);
            drop(_clients_locked);
            trace!("{:?}, Download stream exited...", thread::current().id());
        });
    }
}
