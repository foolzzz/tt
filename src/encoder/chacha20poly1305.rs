#![allow(non_snake_case)]
use chacha20poly1305::ChaCha20Poly1305;
use aead::{NewAead, AeadInPlace};

use crate::utils;
use crate::encoder::EncoderBasicTrait;

#[derive(Clone)]
pub struct ChaCha20 {
    key_bytes: [u8;32],
    size_xor_bytes: [u8;32],
    cipher: ChaCha20Poly1305,
}

impl ChaCha20 {
    pub fn new(KEY:&'static str, otp:u32) -> ChaCha20 {
        ChaCha20 {
            key_bytes:utils::get_key_bytes(KEY, otp),
            size_xor_bytes: utils::get_size_xor_bytes(KEY, otp),
            cipher: ChaCha20Poly1305::new(&utils::get_key_bytes(KEY,otp).into()),
        }
    }

    fn encode_data_size(&self, size: usize, random_bytes:&[u8]) -> [u8;2] {
        //assert!(size<=65536);
        [ 
            (size >> 8) as u8 ^ self.size_xor_bytes[(random_bytes[0] % 32) as usize], 
            (size & 0xff) as u8 ^ self.size_xor_bytes[(random_bytes[1] % 32) as usize]
        ]
    }

    fn decode_data_size(&self, bytes: &[u8], random_bytes: &[u8]) -> usize {
        (
            (((bytes[0] as u16) ^ (self.size_xor_bytes[(random_bytes[0] % 32) as usize]) as u16) << 8) 
            +
            (bytes[1] ^ self.size_xor_bytes[(random_bytes[1] % 32) as usize]) as u16
        ) as usize
    }
    fn encode_random_size(&self, random_bytes:&[u8]) -> u8 {
        (random_bytes.len() as u8) ^ (self.size_xor_bytes[(random_bytes[0] % 32) as usize ])
    }

    fn decode_random_size(&self, random_size:u8, random_bytes_0:u8) -> usize {
        (random_size ^ (self.size_xor_bytes[(random_bytes_0 % 32) as usize])) as usize
    }
}

impl EncoderBasicTrait for ChaCha20{
    fn encode(&self, data: &mut [u8], data_len:usize) -> usize {
        let (random_size, random_bytes) = utils::get_random_bytes();
        let nounce = &random_bytes[ .. 12];
        let aad = &self.key_bytes[ .. 8];
        let data_start = 1 + random_size + 2 + 16;

        let tag = self.cipher.encrypt_in_place_detached(nounce.into(), aad, &mut data[..data_len]).unwrap();
        data.copy_within(0..data_len, data_start);
        data[0] = self.encode_random_size(&random_bytes);
        data[1 .. random_size+ 1].copy_from_slice(&random_bytes);
        data[1 + random_size .. 1 + random_size + 2].copy_from_slice(&self.encode_data_size(data_len, &random_bytes[..2]));
        data[data_start - 16 .. data_start].copy_from_slice(&tag);
        data_start + data_len
    }

    fn decode(&self, data: &mut [u8]) -> (usize, i32) {
        let input_len = data.len();
        let random_size = self.decode_random_size(data[0], data[1]);
        let left_shall_be_read:i32 = (1 + random_size + 2 + 16) as i32 - (input_len as i32);
        if left_shall_be_read > 33 || random_size < 12 {
            return (0, -1)
        }
        else if left_shall_be_read > 0{
            return (0, left_shall_be_read)
        }

        let mut random_bytes = vec![0u8; random_size]; 
        random_bytes.copy_from_slice(&data[1 .. random_size + 1]);

        let data_start = 1 + random_size + 2 + 16;
        let data_len = self.decode_data_size(&data[1+random_size..1+random_size+2], &random_bytes[..2]);
        let left_shall_be_read: i32 = (1 + random_size + 2 + 16 + data_len) as i32 - (input_len as i32);
        if left_shall_be_read > 4096 {
            return (0, -1)
        }
        else if left_shall_be_read > 0  {
            return (0, left_shall_be_read)
        }

        let nounce = &random_bytes[..12];
        let aad = &self.key_bytes[ .. 8];
        let mut tag = vec![0u8;16];
        tag.copy_from_slice(&data[data_start -16 .. data_start]);
        let data = &mut data[data_start .. data_start + data_len];
    
        match self.cipher.decrypt_in_place_detached(nounce.into(), aad, data, tag[..].into()) {
            Ok(_) => (data_len, (data_start + data_len) as i32),
            Err(_) => (0, -1)
        }
    }
}


pub fn _test_encoder() {
    let enc = ChaCha20::new("password12", 11);
    let mut input = vec![0u8;1024];
    &input[..8].copy_from_slice(&[1,2,3,4,5,6,7,8]);
    let size = enc.encode(&mut input, 8);
    println!("encode size:{}\nresult: {:?}", size, &input[..size]);
    let (size, offset) = enc.decode(&mut input[..size]);
    println!("decode size:{}\noffset:{}\nresult: {:?}", size, offset, &input[offset as usize-size .. offset as usize])
}
