use std::io::Read;

use bytes::{Bytes, BufMut, BytesMut};

use crate::{chk_disco, Error, Result};

pub fn read_to_bytes_mut<R: Read>(stream: &mut R, count: usize) -> Result<BytesMut> {
    let mut data = BytesMut::with_capacity(count);
    Ok(unsafe {
        let read = chk_disco!(stream.read(&mut data.bytes_mut()[..count])?);
        data.advance_mut(read);
        data
    })
}
#[inline]
pub fn read_to_bytes<R: Read>(stream: &mut R, count: usize) -> Result<Bytes> {
    Ok(read_to_bytes_mut(stream, count)?.freeze())
}
