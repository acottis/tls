use std::mem::size_of_val;

mod extensions;
use extensions::Extensions;

#[derive(Debug)]
pub struct Tls {
    content_type: u8,
    version: [u8; 2],
    length: u16,
    record: Record<'static>,
}

impl Tls {
    const HEADER_LEN: usize = 5;

    pub fn parse(data: &'static [u8]) -> Result<Self, ()> {
        let content_type = data[0];
        let version = [data[1], data[2]];
        let length = u16::from_be_bytes([data[3], data[4]]);

        let record = Record::parse(
            &data[Self::HEADER_LEN..Self::HEADER_LEN + length as usize],
            content_type,
        );

        Ok(Self {
            content_type,
            version,
            length,
            record: record.unwrap(),
        })
    }
}

#[derive(Debug)]
enum Record<'record> {
    ClientHello(Handshake<'record>),
    Alert(Alert),
}

impl<'record> Record<'record> {
    const HANDSHAKE: u8 = 22;

    fn parse(data: &'record [u8], content_type: u8) -> Result<Self, ()> {
        Ok(match content_type {
            Self::HANDSHAKE => Record::ClientHello(Handshake::parse(&data)?),
            todo => todo!("Implement TLS: {:?}", todo),
        })
    }
}

#[derive(Debug)]
struct CipherSuites([Option<CipherSuite>; CipherSuites::MAX_LIST_SIZE]);

impl CipherSuites {
    const MAX_LIST_SIZE: usize = 256;

    fn parse(bytes: &[u8]) -> Self {
        let mut counter = 0;
        let mut cipher_suites = [None; Self::MAX_LIST_SIZE];
        (0..bytes.len()).step_by(2).for_each(|index| {
            cipher_suites[counter] = CipherSuite::parse(&[bytes[index], bytes[index + 1]]);
            counter += 1;
        });

        Self(cipher_suites)
    }
}

#[derive(Debug)]
struct Handshake<'handshake> {
    r#type: u8,
    length: [u8; 3],
    version: [u8; 2],
    random_time: [u8; 4],
    random_bytes: [u8; 28],
    session_id_length: u8,
    cipher_suites_length: u16,
    cipher_suites: CipherSuites,
    compression_methods_length: u8,
    compression_methods: [u8; 10],
    extensions_length: u16,
    extensions: Extensions<'handshake>,
}

impl<'handshake> Handshake<'handshake> {
    fn parse(record: &'handshake [u8]) -> Result<Self, ()> {
        let mut ptr = 0;

        let r#type = record[ptr];
        ptr += size_of_val(&r#type);

        let length = [record[ptr], record[ptr + 1], record[ptr + 2]];
        ptr += size_of_val(&length);

        let version = [record[ptr], record[ptr + 1]];
        ptr += size_of_val(&version);

        let mut random_time = [0u8; 4];
        random_time.copy_from_slice(&record[ptr..ptr + 4]);
        ptr += size_of_val(&random_time);

        let mut random_bytes = [0u8; 28];
        random_bytes.copy_from_slice(&record[ptr..ptr + 28]);
        ptr += size_of_val(&random_bytes);

        let session_id_length = record[ptr];
        ptr += size_of_val(&session_id_length);

        let cipher_suites_length = u16::from_be_bytes([record[ptr], record[ptr + 1]]);
        ptr += size_of_val(&cipher_suites_length);

        let cipher_suites = CipherSuites::parse(&record[ptr..ptr + cipher_suites_length as usize]);
        ptr += cipher_suites_length as usize;

        let compression_methods_length = record[ptr];
        ptr += size_of_val(&compression_methods_length);

        let mut compression_methods: [u8; 10] = Default::default();
        (0..compression_methods_length as usize)
            .for_each(|i| compression_methods[i] = record[ptr + i]);
        ptr += compression_methods_length as usize;

        let extensions_length = u16::from_be_bytes([record[ptr], record[ptr + 1]]);
        ptr += size_of_val(&extensions_length);

        let extensions = Extensions::parse(&record[ptr..ptr + extensions_length as usize]);

        Ok(Self {
            r#type,
            length,
            version,
            random_time,
            random_bytes,
            session_id_length,
            cipher_suites_length,
            cipher_suites,
            compression_methods_length,
            compression_methods,
            extensions_length,
            extensions,
        })
    }
}

#[derive(Debug)]
struct Alert;

#[derive(Debug, Clone, Copy)]
enum CipherSuite {
    TlsEcdheEcdsaWithAes256GcmSha384,
    TlsEcdheEcdsaWithAes128GcmSha256,
    TlsEcdheRsaWithAes256GcmSha384,
    TlsEcdheRsaWithAes128GcmSha256,
    TlsDheRsaWithAes256GcmSha384,
    TlsDheRsaWithAes128GcmSha256,
    TlsEcdheEcdsaWithAes256CbcSha384,
    TlsEcdheEcdsaWithAes128CbcSha256,
    TlsEcdheRsaWithAes256CbcSha384,
    TlsEcdheRsaWithAes128CbcSha256,
    TlsEcdheEcdsaWithAes256CbcSha,
    TlsEcdheEcdsaWithAes128CbcSha,
    TlsEcdheRsaWithAes256CbcSha,
    TlsEcdheRsaWithAes128CbcSha,
    TlsRsaWithAes256GcmSha384,
    TlsRsaWithAes128GcmSha256,
    TlsRsaWithAes256CbcSha256,
    TlsRsaWithAes128CbcSha256,
    TlsRsaWithAes256CbcSha,
    TlsRsaWithAes128CbcSha,
    TlsRsaWith3desEdeCbcSha,
}

impl CipherSuite {
    fn parse(cipher: &[u8; 2]) -> Option<Self> {
        match cipher {
            [0xc0, 0x2c] => Some(Self::TlsEcdheEcdsaWithAes256GcmSha384),
            [0xc0, 0x2b] => Some(Self::TlsEcdheEcdsaWithAes128GcmSha256),
            [0xc0, 0x30] => Some(Self::TlsEcdheRsaWithAes256GcmSha384),
            [0xc0, 0x2f] => Some(Self::TlsEcdheRsaWithAes128GcmSha256),
            [0x00, 0x9f] => Some(Self::TlsDheRsaWithAes256GcmSha384),
            [0x00, 0x9e] => Some(Self::TlsDheRsaWithAes128GcmSha256),
            [0xc0, 0x24] => Some(Self::TlsEcdheEcdsaWithAes256CbcSha384),
            [0xc0, 0x23] => Some(Self::TlsEcdheEcdsaWithAes128CbcSha256),
            [0xc0, 0x28] => Some(Self::TlsEcdheRsaWithAes256CbcSha384),
            [0xc0, 0x27] => Some(Self::TlsEcdheRsaWithAes128CbcSha256),
            [0xc0, 0x0a] => Some(Self::TlsEcdheEcdsaWithAes256CbcSha),
            [0xc0, 0x09] => Some(Self::TlsEcdheEcdsaWithAes128CbcSha),
            [0xc0, 0x14] => Some(Self::TlsEcdheRsaWithAes256CbcSha),
            [0xc0, 0x13] => Some(Self::TlsEcdheRsaWithAes128CbcSha),
            [0x00, 0x9d] => Some(Self::TlsRsaWithAes256GcmSha384),
            [0x00, 0x9c] => Some(Self::TlsRsaWithAes128GcmSha256),
            [0x00, 0x3d] => Some(Self::TlsRsaWithAes256CbcSha256),
            [0x00, 0x3c] => Some(Self::TlsRsaWithAes128CbcSha256),
            [0x00, 0x35] => Some(Self::TlsRsaWithAes256CbcSha),
            [0x00, 0x2f] => Some(Self::TlsRsaWithAes128CbcSha),
            [0x00, 0x0a] => Some(Self::TlsRsaWith3desEdeCbcSha),
            unknown => {
                println!("Unknown Cipher Suite: {unknown:?}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKET_BYTES: [u8; 195] = [
        0x16, 0x03, 0x03, 0x00, 0xbe, 0x01, 0x00, 0x00, 0xba, 0x03, 0x03, 0x64, 0xd6, 0xa0, 0xbf,
        0x15, 0xf4, 0xe9, 0x44, 0x66, 0x2b, 0x07, 0x09, 0x61, 0x14, 0x57, 0x6f, 0x07, 0xb3, 0xa7,
        0x4f, 0x82, 0xa6, 0xa2, 0xd4, 0x36, 0x3e, 0xc4, 0x10, 0x37, 0xc2, 0x60, 0xdf, 0x00, 0x00,
        0x2a, 0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0x00, 0x9f, 0x00, 0x9e, 0xc0, 0x24,
        0xc0, 0x23, 0xc0, 0x28, 0xc0, 0x27, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x13, 0x00,
        0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a, 0x01, 0x00,
        0x00, 0x67, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02,
        0x01, 0x00, 0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04,
        0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02, 0x06, 0x01,
        0x06, 0x03, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 0x68, 0x74,
        0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
    ];

    #[test]
    fn parse_good_hello() {
        Tls::parse(&PACKET_BYTES).unwrap();
    }
}
