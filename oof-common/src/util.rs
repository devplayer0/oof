use std::io::Read;
use std::net::TcpStream;

use bytes::{Bytes, BufMut, BytesMut};
use bufstream::BufStream;

use crate::{chk_disco, Error, Result};

pub fn read_to_bytes(stream: &mut BufStream<TcpStream>, count: usize) -> Result<Bytes> {
    let mut data = BytesMut::with_capacity(count);
    Ok(unsafe {
        let read = chk_disco!(stream.read(&mut data.bytes_mut()[..count])?);
        data.advance_mut(read);
        data.freeze()
    })
}
