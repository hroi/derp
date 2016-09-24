//! ASN.1 universal types
use core::mem;
use super::*;
use super::{encode_i64, decode_i64};

pub const ENDOFCONTENTS:    u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  0;
pub const BOOLEAN:          u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  1;
pub const INTEGER:          u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  2;
pub const BITSTRING:        u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  3;
pub const OCTETSTRING:      u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  4;
pub const NULL:             u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  5;
pub const OBJECTIDENTIFIER: u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  6;
pub const OBJECTDESCRIPTOR: u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  7;
pub const EXTERNAL:         u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  8;
pub const REAL:             u8 = ber::UNIVERSAL | ber::PRIMITIVE   |  9;
pub const ENUMERATED:       u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 10;
pub const EMBEDDEDPDV:      u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 11;
pub const UTF8STRING:       u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 12;
pub const RELATIVEOID:      u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 13;
pub const RESERVED1:        u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 14;
pub const RESERVED2:        u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 15;
pub const SEQUENCE:         u8 = ber::UNIVERSAL | ber::CONSTRUCTED | 16;
pub const SET:              u8 = ber::UNIVERSAL | ber::CONSTRUCTED | 17;
pub const NUMERICSTRING:    u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 18;
pub const PRINTABLESTRING:  u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 19;
pub const T61STRING:        u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 20;
pub const VIDEOTEXTSTRING:  u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 21;
pub const IA5STRING:        u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 22;
pub const UTCTIME:          u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 23;
pub const GENERALIZEDTIME:  u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 24;
pub const GRAPHICSTRING:    u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 25;
pub const VISIBLESTRING:    u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 26;
pub const GENERALSTRING:    u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 27;
pub const UNIVERSALSTRING:  u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 28;
pub const CHARACTERSTRING:  u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 29;
pub const BMPSTRING:        u8 = ber::UNIVERSAL | ber::PRIMITIVE   | 30;

pub struct Boolean<'bytes> (pub &'bytes [u8]);
pub struct Integer<'bytes> (pub &'bytes [u8]);
pub struct BitString<'bytes> (pub &'bytes [u8]);
pub struct OctetString<'bytes> (pub &'bytes [u8]);
pub struct Null<'bytes> (pub &'bytes [u8]);
pub struct ObjectIdentifier<'bytes> (pub &'bytes [u8]);
pub struct Enumerated<'bytes> (pub &'bytes [u8]);
pub struct Utf8String<'bytes> (pub &'bytes [u8]);
pub struct Sequence<'bytes> (pub &'bytes [u8]);
pub struct Set<'bytes> (pub &'bytes [u8]);
pub struct PrintableString<'bytes> (pub &'bytes [u8]);
pub struct T61String<'bytes> (pub &'bytes [u8]);
pub struct Ia5String<'bytes> (pub &'bytes [u8]);
pub struct UtcTime<'bytes> (pub &'bytes [u8]);
pub struct GeneralizedTime<'bytes> (pub &'bytes [u8]);
pub struct GeneralString<'bytes> (pub &'bytes [u8]);

impl<'bytes> Der<i64> for Integer<'bytes> {

    fn identifier() -> u8 { INTEGER }

    fn encode(i: &i64, o: &mut [u8]) -> DerResult<usize> {
        encode_i64(*i, o)
    }

    fn decode(i: &[u8], o: &mut i64) -> DerResult<usize> {
        decode_i64(i, o).and(Ok(1))
    }
}

impl<'bytes> Der<bool> for Boolean<'bytes> {

    fn identifier() -> u8 { BOOLEAN }

    fn encode(i: &bool, o: &mut [u8]) -> DerResult<usize> {
        if let Some(byte) = o.last_mut() {
            *byte = if *i { 0xff } else { 0x00 };
            Ok(1)
        } else {
            Err(Error::BufTooSmall)
        }
    }

    fn decode(i: &[u8], o: &mut bool) -> DerResult<usize> {
        if i.len() != 1 {
            return Err(Error::Invalid);
        }
        match i[0] {
            0x00 => *o = false,
            0xff => *o = true,
            _ => return Err(Error::Invalid),
        }
        Ok(1)
    }
}

macro_rules! impl_der_stringlike {
    ($life:tt, $t:ty, $id:expr) => {
        impl<$life> Der<[u8]> for $t {

            fn identifier() -> u8 { $id }

            fn encode(i: &[u8], o: &mut [u8]) -> DerResult<usize> {
                if o.len() < i.len() {
                    return Err(Error::BufTooSmall);
                }
                let write_offset = o.len() - i.len();

                &mut o[write_offset..].copy_from_slice(i);

                Ok(i.len())
            }

            fn decode(i: &[u8], o: &mut [u8]) -> DerResult<usize> {
                Self::encode(i, o)
            }
        }
    }
}

impl_der_stringlike!('bytes, OctetString<'bytes>, OCTETSTRING);

impl<'bytes> Der<()> for Null<'bytes> {

    fn identifier() -> u8 { NULL }

    fn encode(_input: &(), _output: &mut [u8]) -> DerResult<usize> {
        Ok(0)
    }

    fn decode(input: &[u8], _output: &mut ()) -> DerResult<usize> {
        if input.is_empty() { Ok(1) } else { Err(Error::Invalid) }
    }
}


impl<'bytes> Der<[u32]> for ObjectIdentifier<'bytes> {

    fn identifier() -> u8 { OBJECTIDENTIFIER }

    fn encode(input: &[u32], output: &mut [u8]) -> DerResult<usize> {
        if input.len() < 2 {
            return Err(Error::Invalid);
        }
        let mut pos = output.len() - 1;

        let (head, tail) = input.split_at(2);

        if head[0] > 2 {
            // first subid must be between 0 - 2.
            return Err(Error::Invalid);
        }
        if head[1] > 39 {
            // second subid must be between 0 - 39.
            return Err(Error::Invalid);
        }
        // encode the subids i reverse order
        for subid in tail.iter().rev() {
            let mut subid = *subid;
            let mut last_byte = true;
            while subid > 0 {

                if pos == 0 {
                    return Err(Error::BufTooSmall);
                }

                if last_byte {
                    // continue bit is cleared
                    output[pos] = (subid & 0b01111111) as u8;
                    last_byte = false;
                } else {
                    // continue bit is set
                    output[pos] = (subid | 0b10000000) as u8;
                }
                pos -= 1;
                subid >>= 7;

                if subid == 0 {
                    break;
                }
            }
        }
        // encode the head last

        output[pos] = (head[0] * 40 + head[1]) as u8;

        Ok(output.len() - pos)
    }

    fn decode(input: &[u8], output: &mut [u32]) -> DerResult<usize> {
        let out_len = {
            if input.len() < 2 {
                return Err(Error::Invalid);
            }
            if output.len() < 2 {
                return Err(Error::BufTooSmall);
            }
            let subid1 = (input[0] / 40) as u32;
            let subid2 = (input[0] % 40) as u32;
            output[0] = subid1;
            output[1] = subid2;
            let mut pos = 2;
            let mut cur_oid: u32 = 0;
            let mut is_done = false;
            let mut num_bytes_in_int = 0;
            for b in &input[1..] {
                if pos == output.len() {
                    return Err(Error::BufTooSmall);
                }
                num_bytes_in_int += 1;
                if num_bytes_in_int > mem::size_of::<u32>() {
                    return Err(Error::IntOverflow);
                }
                is_done = b & 0b10000000 == 0;
                let val = b & 0b01111111;
                cur_oid <<= 7;
                cur_oid |= val as u32;
                if is_done {
                    num_bytes_in_int = 0;
                    output[pos] = cur_oid;
                    pos += 1;
                    cur_oid = 0;
                }
            }
            if !is_done {
                return Err(Error::Invalid)
            } else {
                pos
            }
        };
        Ok(out_len)
    }
}




impl_der_stringlike!('bytes, Utf8String<'bytes>, UTF8STRING);

/// A generic constructed encoding (contains zero or more DER-encoded values within it).
pub struct Construct<'bytes> {
    _inner: &'bytes [u8],
}

impl<'bytes> Der<Construct<'bytes>> for Sequence<'bytes> {
    fn identifier() -> u8 { SEQUENCE }

    fn encode(_input: &Construct, _output: &mut [u8]) -> DerResult<usize> {
        unimplemented!()
    }

    fn decode(_input: &[u8], _output: &mut Construct) -> DerResult<usize> {
        unimplemented!()
    }
}

impl<'bytes> Der<Construct<'bytes>> for Set<'bytes> {
    fn identifier() -> u8 { SET }

    fn encode(_input: &Construct, _output: &mut [u8]) -> DerResult<usize> {
        unimplemented!()
    }

    fn decode(_input: &[u8], _output: &mut Construct) -> DerResult<usize> {
        unimplemented!()
    }
}

impl_der_stringlike!('bytes, PrintableString<'bytes>, PRINTABLESTRING);
impl_der_stringlike!('bytes, T61String<'bytes>, T61STRING);
impl_der_stringlike!('bytes, Ia5String<'bytes>, IA5STRING);
impl_der_stringlike!('bytes, UtcTime<'bytes>, UTCTIME);
impl_der_stringlike!('bytes, GeneralizedTime<'bytes>, GENERALIZEDTIME);
impl_der_stringlike!('bytes, GeneralString<'bytes>, GENERALSTRING);


pub fn parse_der(_input: &[u8]) -> DerResult<Value> {
    unimplemented!()
}

pub enum Value<'bytes> {
    EndOfContents(&'bytes[u8]),
    Boolean(Boolean<'bytes>),
    Integer(Integer<'bytes>),
    BitString(BitString<'bytes>),
    OctetString(OctetString<'bytes>),
    Null(Null<'bytes>),
    ObjectIdentifier(ObjectIdentifier<'bytes>),
    ObjectDescriptor(&'bytes[u8]),
    External(&'bytes[u8]),
    Real(&'bytes[u8]),
    Enumerated(Enumerated<'bytes>),
    EmbeddedPdv(&'bytes[u8]),
    Utf8String(Utf8String<'bytes>),
    RelativeOid(&'bytes[u8]),
    Reserved1(&'bytes[u8]),
    Reserved2(&'bytes[u8]),
    Sequence(Sequence<'bytes>),
    Set(Set<'bytes>),
    NumericString(&'bytes[u8]),
    PrintableString(PrintableString<'bytes>),
    T61String(T61String<'bytes>),
    VideotexString(&'bytes[u8]),
    Ia5String(Ia5String<'bytes>),
    UtcTime(UtcTime<'bytes>),
    GeneralizedTime(GeneralizedTime<'bytes>),
    GraphicString(&'bytes[u8]),
    VisibleString(&'bytes[u8]),
    GeneralString(GeneralString<'bytes>),
    UniversalString(&'bytes[u8]),
    CharacterString(&'bytes[u8]),
    BmpString(&'bytes[u8]),

    Application(&'bytes [u8]),
    ContextSpecific(&'bytes [u8]),
    Private(&'bytes [u8]),
}
