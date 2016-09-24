#![allow(dead_code)]
#![cfg_attr(test, feature(test))]
//! # DERp
//!
//! A library for encoding and decoding ASN.1 DER data.
//!
//! - Efficient
//! - Zero-allocation
//! - STD-free (```#[no_std]``` compatible)

extern crate core;
use core::mem;
use core::ptr;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq)]
/// Encode/decode errors.
pub enum Error {
    /// Invalid encoding encountered.
    Invalid,
    /// Decode resulted in an integer overflow.
    IntOverflow,
    /// Not enough space to store encoded data in output buffer.
    BufTooSmall,
}

pub type DerResult<T> = Result<T, Error>;

pub mod ber {
    //! Basic Encoding Rules constants
    pub const PRIMITIVE:       u8 = 0b00000000;
    pub const CONSTRUCTED:     u8 = 0b00100000;

    pub const UNIVERSAL:       u8 = 0b00000000;
    pub const APPLICATION:     u8 = 0b01000000;
    pub const CONTEXTSPECIFIC: u8 = 0b10000000;
    pub const PRIVATE:         u8 = 0b11000000;
}

pub mod asn1;
pub mod smiv2;

/// Types that implement this trait are DER en-/decodable.
///
/// Note: Because of variable length encoding of length fields, encoding
/// is done in reverse order from the bottom of the output buffer so we avoid
/// moving bytes around to make them fit together.
/// Decoding is done in forward order.
pub trait Der<T: ?Sized> {

    /// Returns first identifier byte for encoding.
    fn identifier() -> u8;

    /// Types with tag > 31 are required to override this method.
    fn tag() -> u64 {
        let tag = Self::identifier() & 0b00011111;
        assert!(tag < 31);
        tag as u64
    }

    /// DER-encodes value referenced by `i` onto byte slice `o`. Implementors must check that `o` has
    /// enough space to encode the value.
    ///
    /// Note: The encoded bytes must be written to the *end* of the buffer.
    ///
    /// On success returns the exact number of bytes encoded.
    fn encode(input: &T, output: &mut [u8]) -> DerResult<usize>;

    /// DER-decode content bytes contained in `i` and write the value onto the location pointed to
    /// by `o`. `o` shall contain _exactly_ the required bytes to decode the value.
    ///
    /// On success returns 1 for scalar values, otherwise length of the output.
    fn decode(input: &[u8], output: &mut T)    -> DerResult<usize>;

    /// DER-encodes type, length and value onto the end of buffer `o`.
    ///
    /// On success returns the amount of bytes encoded.
    fn write_der(input: &T, output: &mut [u8]) -> DerResult<usize> {
        let o_len = output.len();
        let content_length = try!(Self::encode(input, output));
        let (remaining, _) = output.split_at_mut(o_len - content_length);
        let len_length = try!(encode_len(content_length, remaining));
        let rem_len = remaining.len();
        let ident = Self::identifier();
        if ident < 32 {
            remaining[rem_len - len_length - 1] = ident as u8;
        } else {
            // encode extended tag here
            let _tag = Self::tag();
            unimplemented!() // TODO
        }
        Ok(content_length + len_length + 1)
    }
}

/// Encodes a content length onto `o` according to ASN.1 8.1.3.
///
/// On success returns the number of bytes encoded.
fn encode_len(len: usize, o: &mut [u8]) -> DerResult<usize> {
    let o_len = o.len();
    if len < 128 {
        // short form
        o[o_len - 1] = len as u8;
        Ok(1)
    } else {
        // long form

        let num_leading_nulls = (len.leading_zeros() / 8) as usize;
        let length_len = mem::size_of::<usize>() - num_leading_nulls;
        let leading_byte = length_len as u8 | 0b1000_0000;

        if o.len() < length_len + 1 {
            return Err(Error::BufTooSmall);
        }

        let bytes = unsafe { mem::transmute::<usize, [u8; 8]>(len.to_be()) };
        let write_offset = o.len() - length_len - 1;
        o[write_offset] = leading_byte;
        &mut o[write_offset + 1..].copy_from_slice(&bytes[num_leading_nulls..]);

        Ok(length_len + 1)
    }
}

/// Decodes a content length value from `i`.
///
/// On success, returns the number of decoded from `i` and stores
/// the resulting length value at the location referenced by `o`.
fn decode_len(i: &[u8], o: &mut usize) -> DerResult<usize> {
    if let Some((head, tail)) = i.split_first() {
        if head < &128 {
            // short form
            *o = *head as usize;
            Ok(1)
        } else if head == &0xff {
            Err(Error::Invalid) // reserved for future use
        } else {
            // long form
            let length_len = (*head & 0b01111111) as usize;
            if length_len == 0 {
                // Indefinite length. Not allowed in DER.
                return Err(Error::Invalid);
            }

            let mut bytes = [0u8; 8];
            &mut bytes[(mem::size_of::<usize>() - length_len)..].copy_from_slice(&tail[..length_len]);

            *o = unsafe { mem::transmute::<[u8; 8], usize>(bytes).to_be()};
            Ok(length_len as usize + 1)
        }
    } else {
        Err(Error::Invalid)
    }
}

/// Encodes a signed integer onto `o`.
///
/// On success returns the number of bytes encoded.
fn encode_i64(mut n: i64, o: &mut [u8]) -> DerResult<usize> {

    let mut null = 0x00_u8; // two's complement - positive: 0x00, negative: 0xff
    let num_null_bytes = if !n.is_negative() {
        (n.leading_zeros() / 8) as usize
    } else {
        null = 0xff;
        ((!n).leading_zeros() / 8) as usize
    };
    n = n.to_be();

    unsafe {
        let mut src_ptr = &n as *const i64 as *const u8;
        let mut dst_ptr = o.as_mut_ptr().offset(o.len() as isize - mem::size_of::<i64>() as isize);

        let mut count = mem::size_of::<i64>() - num_null_bytes;
        if count == 0 {
            count = 1;
        }

        // preserve sign
        if (*(src_ptr.offset((mem::size_of::<i64>() - count) as isize)) ^ null) > 127u8 {
            count += 1;
        }

        if o.len() < count {
            return Err(Error::BufTooSmall);
        }

        let offset = (mem::size_of::<i64>() - count) as isize;
        src_ptr = src_ptr.offset(offset);
        dst_ptr = dst_ptr.offset(offset);
        ptr::copy_nonoverlapping(src_ptr, dst_ptr, count);

        Ok(count)
    }
}

/// Decodes a signed integer from `i`.
///
/// Note: `i` must contain *exactly* the bytes required to decode the value.
///
/// On success stores the decoded value at the location referenced by `o`.
fn decode_i64(i: &[u8], o: &mut i64) -> DerResult<()> {
    if i.len() > mem::size_of::<i64>() {
        return Err(Error::IntOverflow);
    }
    let mut bytes = [0u8; 8];
    &mut bytes[(mem::size_of::<i64>() - i.len())..].copy_from_slice(i);

    *o = unsafe { mem::transmute::<[u8; 8], i64>(bytes).to_be()};
    {
        //sign extend
        let shift_amount = (mem::size_of::<i64>() - i.len()) * 8;
        *o = (*o << shift_amount) >> shift_amount;
    }
    Ok(())
}

