use std::mem::size_of_val;

#[derive(Debug)]
struct ServerName<'name> {
    list_length: u16,
    r#type: u8,
    length: u16,
    name: &'name [u8],
}
impl<'name> ServerName<'name> {
    fn parse(bytes: &'name [u8]) -> Self {
        let mut ptr = 0;

        let list_length = u16::from_be_bytes([bytes[ptr], bytes[ptr + 1]]);
        ptr += size_of_val(&list_length);

        let r#type = bytes[ptr];
        ptr += size_of_val(&r#type);

        let length = u16::from_be_bytes([bytes[ptr], bytes[ptr + 1]]);
        ptr += size_of_val(&length);

        let name = &bytes[ptr..ptr + length as usize];

        Self {
            list_length,
            r#type,
            length,
            name,
        }
    }
}

#[derive(Debug)]
enum Extension<'extension> {
    ServerName(ServerName<'extension>),
    StatusRequest,
    SupportedGroups,
    EcPointFormats,
    SignatureAlgorithms,
    SessionTicket,
    Alpn,
    ExtendedMasterSecret,
    RenegotiationInfo,
}

impl<'extension> Extension<'extension> {
    const HEADER_LEN: usize = 4;

    fn parse(bytes: &'extension [u8]) -> (Option<Self>, usize) {
        let r#type = [bytes[0], bytes[1]];
        let ext_length = u16::from_be_bytes([bytes[2], bytes[3]]);

        let ext_start = &bytes[Self::HEADER_LEN..];
        let ext = match r#type {
            [0, 0] => Some(Self::ServerName(ServerName::parse(&ext_start))),
            [0, 5] => Some(Self::StatusRequest),
            [0, 10] => Some(Self::SupportedGroups),
            [0, 11] => Some(Self::EcPointFormats),
            [0, 13] => Some(Self::SignatureAlgorithms),
            [0, 35] => Some(Self::SessionTicket),
            [0, 16] => Some(Self::Alpn),
            [0, 23] => Some(Self::ExtendedMasterSecret),
            [255, 1] => Some(Self::RenegotiationInfo),
            unknown => {
                println!("Unknown Extension Type: {unknown:?}");
                None
            }
        };
        (ext, Self::HEADER_LEN + ext_length as usize)
    }
}

#[derive(Debug)]
pub struct Extensions<'extensions>([Option<Extension<'extensions>>; Extensions::MAX_EXTENSIONS]);

impl<'extensions> Extensions<'extensions> {
    const MAX_EXTENSIONS: usize = 20;

    pub fn parse(bytes: &'extensions [u8]) -> Self {
        let mut counter = 0;
        let mut ptr = 0;
        let mut extensions: [Option<Extension>; Extensions::MAX_EXTENSIONS] = Default::default();
        loop {
            if ptr >= bytes.len() {
                break;
            }

            let (ext, len) = Extension::parse(&bytes[ptr..]);
            ptr += len;

            extensions[counter] = ext;
            counter += 1;
        }
        Self(extensions)
    }
}
