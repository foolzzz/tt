#![allow(non_snake_case)]
extern crate log;
extern crate lazy_static;

use std::net;
use std::time;
use std::thread;
use std::process;
use std::sync::{Arc, Mutex, mpsc};

use crate::utils;
use lazy_static::lazy_static;

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

#[cfg(not(target_os = "windows"))]
use crate::server_tun;
use crate::server_proxy;
use crate::encoder::{Encoder, EncoderMethods};
use crate::encoder::aes256gcm::AES256GCM;
use crate::encoder::chacha20poly1305::ChaCha20;

lazy_static! {
    static ref TUN_MODE:    Mutex<bool> = Mutex::new(false);
    static ref PROXY_MODE: Mutex<bool> = Mutex::new(false);
    static ref NO_PORT_JUMP:Mutex<bool> = Mutex::new(false);
}

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, BIND_ADDR:&'static str, 
            PORT_START: u32, PORT_END: u32, BUFFER_SIZE: usize, TUN_IP: Option<String>,
            MTU: usize, _NO_PORT_JUMP: bool, _NO_PROXY: bool) {

    let (tx_tun, rx_tun) = mpsc::channel();
    let (tx_proxy, rx_proxy) = mpsc::channel();
    *NO_PORT_JUMP.lock().unwrap() = _NO_PORT_JUMP;

    *TUN_MODE.lock().unwrap() = match TUN_IP{
        Some(tun_ip) => {
            if cfg!(target_os = "windows") {
                error!("Error: tun mode does not support windows for now");
                process::exit(-1);
            }
            #[cfg(not(target_os = "windows"))]
            {
                info!("TT {}, Server (tun mode)", env!("CARGO_PKG_VERSION"));
                thread::spawn( move || server_tun::handle_connection(rx_tun, BUFFER_SIZE, &tun_ip, MTU));
            }
            true
        },
        None => false
    };

    *PROXY_MODE.lock().unwrap() = match _NO_PROXY {
        false => {
            info!("TT {}, Server (proxy mode)", env!("CARGO_PKG_VERSION"));
            thread::spawn( move || server_proxy::handle_connection(rx_proxy, BUFFER_SIZE));
            true
        },
        true => false
    };

    let mut time_now = utils::get_secs_now();
    let time_start = if (PORT_END - PORT_START) > 2
                        && utils::get_port(utils::get_otp(KEY, time_now/60 - 1), PORT_START, PORT_END)
                            != utils::get_port(utils::get_otp(KEY, time_now/60), PORT_START, PORT_END){
        time_now/60 - 1
    }
    else{
        time_now/60
    };

    for i in time_start .. (time_now/60 + 2) {
        let _tx_tun = tx_tun.clone();
        let _tx_proxy = tx_proxy.clone();
        thread::spawn( move || start_listener(_tx_tun, _tx_proxy, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, i));
        thread::sleep(time::Duration::from_millis(100));
    }

    loop {
        // wait 2 more secs, let conflicted port to close itself,
        // and not conflict with any thread that waiting for this same port
        //
        thread::sleep(time::Duration::from_secs( 60 - (time_now % 60) + 2 ));
        time_now = utils::get_secs_now();

        let _tx_tun = tx_tun.clone();
        let _tx_proxy = tx_proxy.clone();
        thread::spawn( move || start_listener(
            _tx_tun, _tx_proxy, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now/60 + 1)
        );
    }

    /*
    let mut sched = JobScheduler::new();
    sched.add(Job::new("0 * * * * *".parse().unwrap(), || {
        thread::spawn( move || start_listener(
                KEY, BIND_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, utils::get_secs_now()/60 + 1));
    }));
    loop {
        sched.tick();
        std::thread::sleep(time::Duration::from_millis(500));
    }
    */
}

fn start_listener(tx_tun: mpsc::Sender<(net::TcpStream, Encoder)>, tx_proxy: mpsc::Sender<(net::TcpStream, Encoder)>,
        KEY:&'static str, METHOD:&EncoderMethods, BIND_ADDR:&'static str,
        PORT_RANGE_START:u32, PORT_RANGE_END:u32, time_start:u64) {
    let otp = utils::get_otp(KEY, time_start);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let lifetime = utils::get_lifetime(otp);
    let encoder = match METHOD {
        EncoderMethods::AES256 => Encoder::AES256(AES256GCM::new(KEY, otp)),
        EncoderMethods::ChaCha20 => Encoder::ChaCha20(ChaCha20::new(KEY, otp)),
    };
    debug!("Open port : [{}], lifetime: [{}]", port, lifetime);

    let streams = Arc::new(Mutex::new(Vec::new())); 
    let flag_stop = Arc::new(Mutex::new(0));
/*
    let listener = match net::TcpListener::bind(format!("{}:{}", BIND_ADDR, port)) {
        Ok(listener) => listener,
        Err(err) => {
            error!("Error binding port: [{}], {}", port, err);
            return
        }
    };

*/
    let listener;
    let mut retry = 0;
    loop {
        match net::TcpListener::bind(format!("{}:{}", BIND_ADDR, port)) {
            Ok(_listener) => {
                listener = _listener;
                break;
            },
            Err(err) if err.kind() != std::io::ErrorKind::AddrInUse => {
                error!("Error binding port: [{}], {:?}", port, err);
                return
            },
            Err(_) => debug!("Port: [{}] in use, {:?}, retry in 2 secs...", port, thread::current().id())
        }
        retry += 1;
        thread::sleep(time::Duration::from_secs(2));
        if retry >= 33 {     // give up after 66 secs
            error!("Failed binding port: [{}], after {} secs", port, retry * 2);
            return
        }
    }

    /*  1. not using JobScheduler, cause it adds too much stupid code here.
     *  2. can't find a proper way to drop listener inside _timer_thread, 
     *     tried: Box + raw pointer, Arc<Mutex<listener>>...
     *  3. So we use 'flag_stop' to transfer the status, and connect to the port to break
     *     the main thread from listener.incoming()
     */
    let _streams = Arc::clone(&streams);
    let _flag_stop = Arc::clone(&flag_stop);
    let mut time_now = utils::get_secs_now();
    let _timer_thread = thread::spawn(move || {
        loop {
            thread::sleep(time::Duration::from_secs( 60 - (time_now % 60) ));   // once a minute
            time_now = utils::get_secs_now();
            let time_diff = match time_now/60 >= time_start {
                true => (time_now/60 - time_start) as u8,
                false => continue
            };

            // check lifetime
            if time_diff >= lifetime || time_diff > 2 && _streams.lock().unwrap().len() == 0 {
                *_flag_stop.lock().unwrap() = 1;
                break;
            }
            // avoid conflicted ports, stop listening, but do not kill established connections
            else if time_diff > 0 &&
                (utils::get_port(utils::get_otp(KEY, time_now/60), PORT_RANGE_START, PORT_RANGE_END) == port
                    || utils::get_port(utils::get_otp(KEY, time_now/60+1), PORT_RANGE_START, PORT_RANGE_END) == port ){
                *_flag_stop.lock().unwrap() = (lifetime - time_diff) as usize;
                break;
            }
        }
        net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    });

    let mut buf_peek = [0u8; 4096];
    for stream in listener.incoming() {
        if *flag_stop.lock().unwrap() > 0 {         // 0: ok;  1: stop normally;  > 1: stop but sleep some time to kill streams
            drop(listener); 
            break; 
        };
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue                      // try not to panic on error "Too many open files"
        };
        let _stream = match stream.try_clone() {
            Ok(_stream) => _stream,
            Err(_) => continue,                     // same as above
        };

        let tx_tun = tx_tun.clone();
        let tx_proxy = tx_proxy.clone();
        let streams = streams.clone();
        let _encoder = encoder.clone();
        thread::spawn( move || {
            let mut offset = 0;
            let mut data_len = 0;
            let mut count = 10;
            while count > 0 {
                _stream.set_read_timeout(Some(time::Duration::from_secs( rand::random::<u8>() as u64 + 60 ))).unwrap();
                let len = match _stream.peek(&mut buf_peek){
                    Ok(len) if len > 1 => len,
                    _ => return
                };
                let (_data_len, _offset) = _encoder.decode(&mut buf_peek[..len]);
                if _data_len == 0 && _offset > 0 {             // need to read more
                    //debug!("peek length: {}, data length: {}, lets continue", len, _data_len);
                    thread::sleep(time::Duration::from_millis(200));
                    count -= 1;
                    continue
                }
                offset = _offset;
                data_len = _data_len;
                break
            }

            let index = offset as usize - data_len;
            if *PROXY_MODE.lock().expect("PROXY_MODE lock failed") && data_len > 2
                && (
                    (data_len == 2 + buf_peek[index + 1] as usize) && buf_peek[index] == 0x05
                    || &buf_peek[index .. index + 7] == "CONNECT".as_bytes()
                    || &buf_peek[index .. index + 3] == "GET".as_bytes()
                    || &buf_peek[index .. index + 3] == "PUT".as_bytes()
                    || &buf_peek[index .. index + 4] == "POST".as_bytes()
                    || &buf_peek[index .. index + 4] == "HEAD".as_bytes()
                    || &buf_peek[index .. index + 6] == "DELETE".as_bytes()
                    || &buf_peek[index .. index + 7] == "OPTIONS".as_bytes()
                ){
                tx_proxy.send((_stream, _encoder)).expect("Failed: tx_proxy.send()");
                return                                      // no need to push proxy stream to die
            }
            // IP header length: v4>=20, v6>=40, our defined first packet: v4=5, v6=...
            else if *TUN_MODE.lock().expect("TUN_MODE lock failed") && data_len >= 5
                && (buf_peek[index]>>4 == 0x4 || buf_peek[index]>>4 == 0x6){
                    tx_tun.send((_stream, _encoder)).unwrap();
            }
            streams.lock().unwrap().push(stream);       // push wild streams here, waiting to die
        });
    }
    debug!("Close port: [{}], lifetime: [{}]", port, lifetime);
    
    // If we kill all the existing streams, then the client has to establish a new one to
    // resume connection. Also, if we kill streams at the very first seconeds of each
    // minute, this seems to be a traffic pattern.
    
    thread::sleep(time::Duration::from_secs(
        (
            ( *flag_stop.lock().unwrap() -1 ) * 60
            +
            ( rand::random::<u8>() % 30 ) as usize
        ) as u64 ));

    if !*NO_PORT_JUMP.lock().unwrap(){
        for stream in &*streams.lock().unwrap(){
            stream.shutdown(net::Shutdown::Both).unwrap_or_else(|_err|());
            drop(stream)
        }
    }
}
