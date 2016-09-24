//! SMIv2 types.
use super::*;
use super::{encode_i64, decode_i64};

pub const IPADDRESS:  u8 = ber::APPLICATION | ber::PRIMITIVE | 0;
pub const COUNTER32:  u8 = ber::APPLICATION | ber::PRIMITIVE | 1;
pub const GAUGE32:    u8 = ber::APPLICATION | ber::PRIMITIVE | 2;
pub const UNSIGNED32: u8 = ber::APPLICATION | ber::PRIMITIVE | 2; // same as Gauge32
pub const TIMETICKS:  u8 = ber::APPLICATION | ber::PRIMITIVE | 3;
pub const OPAQUE:     u8 = ber::APPLICATION | ber::PRIMITIVE | 4;
pub const COUNTER64:  u8 = ber::APPLICATION | ber::PRIMITIVE | 6;

pub struct IpAddress;
pub struct Counter32;
pub struct Gauge32;
pub struct Unsigned32;
pub struct TimeTicks;
pub struct Opaque;
pub struct Counter64;

macro_rules! impl_encdec_unsigned {
    ($p:ty, $id:expr, $t:ty) => {
        impl<'bytes> Der<$p> for $t {

            fn identifier() -> u8 { $id }

            fn encode(i: & $p, o: &mut [u8]) -> DerResult<usize> {
                encode_i64(*i as i64, o)
            }

            fn decode(i: &[u8], o: &mut $p) -> DerResult<usize> {
                let mut n = 0i64;
                try!(decode_i64(i, &mut n));
                if n > (!0 as $p) as i64 || n.is_negative() {
                    return Err(Error::Invalid);
                }
                *o = n as $p;
                Ok(1)
            }
        }
    }
}

impl_encdec_unsigned!(u32, COUNTER32,  Counter32);
impl_encdec_unsigned!(u32, GAUGE32,    Gauge32);
impl_encdec_unsigned!(u32, UNSIGNED32, Unsigned32);
impl_encdec_unsigned!(u64, COUNTER64,  Counter64); // XXX: does this work for values greater than 2**63?

pub fn parse_der(input: &[u8]) -> DerResult<Value> {
    use self::Value as V;
    if let Some((head, tail)) = input.split_first() {
        match *head {
            IPADDRESS => Ok(V::IpAddress(asn1::OctetString(tail))),
            COUNTER32 => Ok(V::Counter32(asn1::Integer(tail))),
            GAUGE32 => Ok(V::Gauge32(asn1::Integer(tail))),
            //UNSIGNED32 => Ok(V::Unsigned32(asn1::Integer(tail))),
            TIMETICKS => Ok(V::TimeTicks(asn1::Integer(tail))),
            OPAQUE => Ok(V::Opaque(asn1::OctetString(tail))),
            COUNTER64 => Ok(V::Counter64(asn1::Integer(tail))),
            _ => asn1::parse_der(input).map(|val| V::Asn1(val)),
        }
    } else {
        Err(Error::Invalid)
    }
}

pub enum Value<'bytes> {
    IpAddress(asn1::OctetString<'bytes>),
    Counter32(asn1::Integer<'bytes>),
    Gauge32(asn1::Integer<'bytes>),
    TimeTicks(asn1::Integer<'bytes>),
    Opaque(asn1::OctetString<'bytes>),
    Counter64(asn1::Integer<'bytes>),
    Asn1(asn1::Value<'bytes>),
}
