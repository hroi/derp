use super::*;
use super::{encode_i64, decode_i64, encode_len, decode_len};
extern crate test;

//
// BER
//

const INTEGER_ENCODINGS: &'static [(i64, &'static [u8])] =
    &[(                   0,                               &[0]),
      (                   1,                               &[1]),
      (                  -1,                             &[255]),
      (                 100,                             &[100]),
      (                -100,                             &[156]),
      (                 200,                           &[0,200]),
      (                -200,                          &[255,56]),
      (               30000,                          &[117,48]),
      (              -30000,                         &[138,208]),
      (               60000,                        &[0,234,96]),
      (              -60000,                      &[255,21,160]),
      ( 9223372036854775807, &[127,255,255,255,255,255,255,255]),
      (-9223372036854775808,               &[128,0,0,0,0,0,0,0]),];

const BUF_LEN: usize = 2 * 1024;

#[test]
fn test_encode_i64 () {
    let mut buf = [0u8; BUF_LEN];
    for &(x, expected) in INTEGER_ENCODINGS {
        let len = encode_i64(x, &mut buf[..]).unwrap();
        let result = &buf[(buf.len() - len)..];
        assert_eq!(result, expected);
    }
}

#[test]
fn test_decode_i64 () {
    for &(expected, bytes) in INTEGER_ENCODINGS {
        let mut result = 0i64;
        decode_i64(bytes, &mut result).unwrap();
        assert_eq!(result, expected);
    }
}

#[test]
fn test_encode_i64_buf_overflow() {
    let mut buf = [0u8; 1];
    assert_eq!(encode_i64(255i64, &mut buf[..]), Err(Error::BufTooSmall));
}

#[test]
fn test_decode_i64_int_overflow() {
    let buf = [255u8; 9];
    let mut n = 0i64;
    assert_eq!(decode_i64(&buf[..], &mut n), Err(Error::IntOverflow));
}

#[bench]
fn bench_decode_i64(bench: &mut test::Bencher) {
    let min: &[u8] = &[128,0,0,0,0,0,0,0];
    // let max: &[u8] = &[127,255,255,255,255,255,255,255];
    // let zero: &[u8] = &[0];
    let mut res = 0i64;
    bench.iter(|| {
        (decode_i64(min, &mut res), res)
    });
}

#[bench]
fn bench_encode_i64(bench: &mut test::Bencher) {
    let mut buf = [0u8; BUF_LEN];
    bench.iter(|| {
        (encode_i64(i64::min_value(), &mut buf[..]), buf[BUF_LEN - 1])
    });
}

#[test]
fn test_endec_content_length() {
    let mut buf = [0u8; BUF_LEN];
    let mut content_length = 0usize;

    for &i in &[0,1,10,100,200,30000,60000] {
        // encode
        let len = encode_len(i, &mut buf[..]).unwrap();
        let (_, encoded) = buf.split_at(BUF_LEN - len);
        println!("{} encoded: {:?}", i, encoded);

        //decode
        decode_len(encoded, &mut content_length).unwrap();

        assert_eq!(i, content_length);
    }
}


//
// ASN.1 Boolean
//

#[test]
fn test_encode_boolean() {
    let mut buf = [0u8; BUF_LEN];
    let len = asn1::Boolean::encode(&true, &mut buf).unwrap();
    assert_eq!(&buf[(BUF_LEN - len)..], &[0xff]);
    let len = asn1::Boolean::encode(&false, &mut buf).unwrap();
    assert_eq!(&buf[(BUF_LEN - len)..], &[0x00]);
}

#[test]
fn test_decode_boolean() {
    let yes = &[0xff_u8];
    let no  = &[0x00_u8];
    let invalid = &[0xaa];
    let wrong_length = &[0x00, 0x00];
    let mut result = false;

    asn1::Boolean::decode(yes, &mut result).unwrap();
    assert_eq!(result, true);
    asn1::Boolean::decode(no, &mut result).unwrap();
    assert_eq!(result, false);
    assert!(asn1::Boolean::decode(invalid, &mut result).is_err());
    assert!(asn1::Boolean::decode(wrong_length, &mut result).is_err());
}

#[test]
fn test_write_der_boolean() {
    let mut buf = [0u8; BUF_LEN];

    {
        let len = asn1::Boolean::write_der(&true, &mut buf[..]).unwrap();
        let (_, encoded) = buf.split_at(BUF_LEN - len);
        assert_eq!(encoded, &[1, 1, 255]);
    }
    {
        let len = asn1::Boolean::write_der(&false, &mut buf[..]).unwrap();
        let (_, encoded) = buf.split_at(BUF_LEN - len);
        assert_eq!(encoded, &[1, 1, 0]);
    }
}

#[test]
fn test_write_der_integer() {
    let mut buf = [0u8; BUF_LEN];
    let len = asn1::Integer::write_der(&9223372036854775807, &mut buf[..]).unwrap();
    let (_, encoded) = buf.split_at(BUF_LEN - len);
    println!("{:?}", encoded);
}

#[test]
fn test_write_der_octetstring() {
    let mut buf = [0u8; BUF_LEN];
    let octets   = &[1u8,2,3,4,5,6,7,8];
    let expected = &[asn1::OCTETSTRING, octets.len() as u8, 1u8,2,3,4,5,6,7,8];
    let len = asn1::OctetString::write_der(octets, &mut buf[..]).unwrap();
    let (_, encoded) = buf.split_at(BUF_LEN - len);
    println!("{:?}", encoded);
    assert_eq!(encoded, expected);
}

//
// ASN.1 OctetString
//

#[test]
fn test_encode_octetstring() {
    let mut buf = [0u8; BUF_LEN];
    let octets   = &[1u8,2,3,4,5,6,7,8];
    let expected = octets.clone();
    let len = asn1::OctetString::encode(octets, &mut buf[..]).unwrap();
    let (_, encoded) = buf.split_at(BUF_LEN - len);
    assert_eq!(encoded, expected);
}

#[test]
fn test_decode_octetstring() {
    let mut buf = [0u8; BUF_LEN];
    let octets   = &[1u8,2,3,4,5,6,7,8];
    asn1::OctetString::decode(octets, &mut buf[(BUF_LEN - octets.len())..]).unwrap();
    let (_, encoded) = buf.split_at(BUF_LEN - octets.len());
    assert_eq!(encoded, octets);
}

//
// ASN.1 Null
//

#[test]
fn test_encode_null() {
    let mut buf = [0u8; BUF_LEN];
    let len = asn1::Null::encode(&(), &mut buf[..]).unwrap();
    let (_, encoded) = buf.split_at(BUF_LEN - len);
    assert_eq!(encoded, &[]);
}

#[test]
fn test_decode_null() {
    let bytes = [0u8; 0];
    let mut null = ();
    asn1::Null::decode(&bytes[..], &mut null).unwrap();
}

//
// ASN.1 ObjectIdentifier
//

const OBJID_ENCODINGS: &'static [(&'static [u32], &'static [u8])] = &[
    // sha1WithRSAEncryption
    (&[1, 2, 840, 113549, 1, 1, 5], &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]),
    // IF-MIB::ifHCInOctets.58
    (&[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 58], &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x1f, 0x01, 0x01, 0x01, 0x06, 0x3a,]),
];

#[test]
fn test_encode_objectidentifier() {
    let mut buf = [0u8; BUF_LEN];

    for &(oid, expected) in OBJID_ENCODINGS {
        let len = asn1::ObjectIdentifier::encode(oid, &mut buf[..]).unwrap();
        let (_, encoded) = buf.split_at(BUF_LEN - len);
        assert_eq!(encoded, expected);
    }

}

#[test]
fn test_decode_objectidentifier() {
    for &(expected, encoded) in OBJID_ENCODINGS {
        let mut oidbuf = [0; 128];
        let len = asn1::ObjectIdentifier::decode(encoded, &mut oidbuf[..]).unwrap();
        assert_eq!(&oidbuf[..len], expected);
    }
}

#[test]
fn test_encode_sequence() {
    let mut buf = [0u8; BUF_LEN];

    let len = asn1::Sequence::encode(&[]);
}

#[bench]
fn bench_encode_objectidentifier(b: &mut test::Bencher) {
    let mut buf = [0u8; BUF_LEN];
    let oid = OBJID_ENCODINGS[0].0;
    b.iter(|| {
        let len = asn1::ObjectIdentifier::encode(oid, &mut buf[..]).unwrap();
        test::black_box(&buf[..len]);
    });

}

#[bench]
fn bench_decode_objectidentifier(b: &mut test::Bencher) {
    let mut oidbuf: [u32; 128] = [0; 128];

    b.iter(|| {
        let len = asn1::ObjectIdentifier::decode(OBJID_ENCODINGS[0].1, &mut oidbuf).unwrap();
        test::black_box(&oidbuf[..len]);
    });
}
