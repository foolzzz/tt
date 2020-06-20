#![allow(non_snake_case)]
extern crate oath;
extern crate rand;
extern crate sha2;

use rand::Rng;
use std::time;
use std::error;
use sha2::{Sha256, Digest};
use std::net::Ipv4Addr;

pub mod my_log;

#[cfg(target_os = "linux")]
pub mod route;
#[cfg(not(target_os = "windows"))]
pub mod tun_fd;
#[cfg(not(target_os = "windows"))]
pub mod unix_seqpacket;

pub fn get_secs_now() -> u64 {
    let sys_time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    sys_time.as_secs()
}

pub fn sha256_bytes(data:&str) -> [u8;32] {
    let mut buf  = [0u8;32];
    let mut hasher = Sha256::new();
    hasher.input(data.as_bytes());
    buf.copy_from_slice(hasher.result().as_slice());
    buf
}

pub fn get_key_bytes(key:&str, otp:u32) -> [u8;32] {
    let mut key = key.to_string();
    key.push_str(&format!("ThE=TuNnEL+SaLt-[];',/{}", otp));
    sha256_bytes(&key)
}

pub fn get_size_xor_bytes(key:&str, otp:u32) -> [u8;32] {
    let mut key = key.to_string();
    key.push_str(&format!("SaLT.fOr/SiZe+=Xor-{}", otp));
    sha256_bytes(&key)
}

pub fn get_random_bytes() -> (usize, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut length = rng.gen_range(12, 33);
    let mut result = Vec::with_capacity(length);
    while length > 0  {
        result.push(rng.gen::<u8>());
        length -= 1;
    };
    (length, result)
}

pub fn get_otp(KEY:&str, time_minutes:u64) -> u32 {
    oath::hotp_raw(&sha256_bytes(KEY),  time_minutes, 6) as u32
}

pub fn get_port(otp:u32, PORT_RANGE_START:u32, PORT_RANGE_END:u32) -> u32 {
    if PORT_RANGE_START == PORT_RANGE_END {
        PORT_RANGE_START
    }
    else {
        otp % (PORT_RANGE_END - PORT_RANGE_START) + PORT_RANGE_START
    }
}

pub fn get_lifetime(otp:u32) -> u8 {
    (otp % 15 + 1) as u8
}

pub fn parse_CIDR(cidr: &str) -> Result<(Ipv4Addr, Ipv4Addr), Box<dyn error::Error>> {
    let cidr: Vec<&str> = cidr.trim_matches('.').split("/").collect();
    //assert!(cidr.len() > 0);
    if cidr.len() <= 0 {
        return Err("IP format invalid".into());
    }

    //let addr = cidr[0].into_address()?;     // string to address, using tun::IntoAddress
    let addr = {
        let tmp: Vec<&str> = cidr[0].split(".").collect();
        //assert!(tmp.len() == 4);
        if tmp.len() != 4 {
            return Err("IP format invalid".into());
        }

        Ipv4Addr::new(tmp[0].parse::<u8>()?,
                    tmp[1].parse::<u8>()?,
                    tmp[2].parse::<u8>()?,
                    tmp[3].parse::<u8>()?,
            )
    };

    let mask = match cidr.len() {
        2 => {
            let mask: u32 = cidr[1].parse::<u32>()?;
            assert!(mask <= 32);
            let mask = ( u32::pow(2, mask) -1 ) << (32 - mask);
            //mask.into_address()?;     // int to address, the tun::IntoAddress does it wrong
            Ipv4Addr::new(
			((mask >> 24) & 0xff) as u8,
			((mask >> 16) & 0xff) as u8,
			((mask >> 8 ) & 0xff) as u8,
			((mask >> 0 ) & 0xff) as u8
                )
        }
        _ => Ipv4Addr::new(255,255,255,0)                                   // netmask default to /24
    };
    Ok((addr, mask))
}
