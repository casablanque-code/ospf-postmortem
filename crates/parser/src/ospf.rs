// ospf.rs — парсим OSPF пакеты (RFC 2328)
// Нас интересуют все 5 типов: Hello, DBD, LSR, LSU, LSAck

use nom::{bytes::complete::take, number::complete::{be_u8, be_u16, be_u32}, IResult};

/// OSPF типы пакетов
#[derive(Debug, Clone, PartialEq)]
pub enum OspfType {
    Hello,
    DatabaseDescription,
    LinkStateRequest,
    LinkStateUpdate,
    LinkStateAck,
    Unknown(u8),
}

impl From<u8> for OspfType {
    fn from(v: u8) -> Self {
        match v {
            1 => OspfType::Hello,
            2 => OspfType::DatabaseDescription,
            3 => OspfType::LinkStateRequest,
            4 => OspfType::LinkStateUpdate,
            5 => OspfType::LinkStateAck,
            n => OspfType::Unknown(n),
        }
    }
}

impl std::fmt::Display for OspfType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OspfType::Hello => write!(f, "Hello"),
            OspfType::DatabaseDescription => write!(f, "DBD"),
            OspfType::LinkStateRequest => write!(f, "LSR"),
            OspfType::LinkStateUpdate => write!(f, "LSU"),
            OspfType::LinkStateAck => write!(f, "LSAck"),
            OspfType::Unknown(n) => write!(f, "Unknown({})", n),
        }
    }
}

/// Общий OSPF хедер (24 байта)
#[derive(Debug, Clone)]
pub struct OspfHeader {
    pub version: u8,
    pub msg_type: OspfType,
    pub packet_len: u16,
    pub router_id: [u8; 4],
    pub area_id: [u8; 4],
    pub checksum: u16,
    pub auth_type: u16,  // 0=none, 1=simple, 2=MD5
}

impl OspfHeader {
    pub fn router_id_str(&self) -> String {
        format!("{}.{}.{}.{}", self.router_id[0], self.router_id[1], self.router_id[2], self.router_id[3])
    }
    pub fn area_id_str(&self) -> String {
        format!("{}.{}.{}.{}", self.area_id[0], self.area_id[1], self.area_id[2], self.area_id[3])
    }
}

/// Hello пакет — самый важный для нас
#[derive(Debug, Clone)]
pub struct OspfHello {
    pub header: OspfHeader,
    pub network_mask: [u8; 4],
    pub hello_interval: u16,
    pub options: u8,
    pub router_priority: u8,
    pub dead_interval: u32,
    pub designated_router: [u8; 4],
    pub backup_dr: [u8; 4],
    pub neighbors: Vec<[u8; 4]>,
}

impl OspfHello {
    pub fn dr_str(&self) -> String {
        ip_to_str(&self.designated_router)
    }
    pub fn bdr_str(&self) -> String {
        ip_to_str(&self.backup_dr)
    }
    pub fn mask_str(&self) -> String {
        ip_to_str(&self.network_mask)
    }
}

/// LSA хедер (20 байт) — используется в LSU и LSAck
#[derive(Debug, Clone)]
pub struct LsaHeader {
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: u8,
    pub link_state_id: [u8; 4],
    pub advertising_router: [u8; 4],
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl LsaHeader {
    pub fn ls_type_str(&self) -> &'static str {
        match self.ls_type {
            1 => "Router-LSA",
            2 => "Network-LSA",
            3 => "Summary-LSA (Network)",
            4 => "Summary-LSA (ASBR)",
            5 => "AS-External-LSA",
            7 => "NSSA-External-LSA",
            _ => "Unknown-LSA",
        }
    }
    pub fn advertising_router_str(&self) -> String {
        ip_to_str(&self.advertising_router)
    }
    pub fn link_state_id_str(&self) -> String {
        ip_to_str(&self.link_state_id)
    }
}

/// LSU — содержит один или несколько LSA
#[derive(Debug, Clone)]
pub struct OspfLsu {
    pub header: OspfHeader,
    pub lsa_headers: Vec<LsaHeader>,
}

/// DBD — Database Description (для обнаружения MTU mismatch)
#[derive(Debug, Clone)]
pub struct OspfDbd {
    pub header: OspfHeader,
    pub interface_mtu: u16,
    pub options: u8,
    pub flags: u8,           // I=init, M=more, MS=master
    pub dd_sequence: u32,
    pub lsa_headers: Vec<LsaHeader>,
}

impl OspfDbd {
    pub fn is_init(&self) -> bool { self.flags & 0x04 != 0 }
    pub fn is_master(&self) -> bool { self.flags & 0x01 != 0 }
    pub fn is_more(&self) -> bool { self.flags & 0x02 != 0 }
}

/// Unified enum — результат парсинга
#[derive(Debug, Clone)]
pub enum OspfPacket {
    Hello(OspfHello),
    Dbd(OspfDbd),
    Lsu(OspfLsu),
    // LSR и LSAck пока храним как raw header + данные
    Other(OspfHeader),
}

impl OspfPacket {
    pub fn header(&self) -> &OspfHeader {
        match self {
            OspfPacket::Hello(h) => &h.header,
            OspfPacket::Dbd(d) => &d.header,
            OspfPacket::Lsu(l) => &l.header,
            OspfPacket::Other(h) => h,
        }
    }
}

// ── Парсеры ──────────────────────────────────────────────────────────────────

fn parse_ospf_header(input: &[u8]) -> IResult<&[u8], OspfHeader> {
    let (input, version) = be_u8(input)?;
    let (input, msg_type_raw) = be_u8(input)?;
    let (input, packet_len) = be_u16(input)?;
    let (input, rid) = take(4usize)(input)?;
    let (input, area) = take(4usize)(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, auth_type) = be_u16(input)?;
    // 8 байт auth data — пропускаем
    let (input, _auth_data) = take(8usize)(input)?;

    Ok((input, OspfHeader {
        version,
        msg_type: OspfType::from(msg_type_raw),
        packet_len,
        router_id: [rid[0], rid[1], rid[2], rid[3]],
        area_id: [area[0], area[1], area[2], area[3]],
        checksum,
        auth_type,
    }))
}

fn parse_lsa_header(input: &[u8]) -> IResult<&[u8], LsaHeader> {
    let (input, ls_age) = be_u16(input)?;
    let (input, options) = be_u8(input)?;
    let (input, ls_type) = be_u8(input)?;
    let (input, lsid) = take(4usize)(input)?;
    let (input, adv_r) = take(4usize)(input)?;
    let (input, seq) = be_u32(input)?;
    let (input, cksum) = be_u16(input)?;
    let (input, length) = be_u16(input)?;

    Ok((input, LsaHeader {
        ls_age,
        options,
        ls_type,
        link_state_id: [lsid[0], lsid[1], lsid[2], lsid[3]],
        advertising_router: [adv_r[0], adv_r[1], adv_r[2], adv_r[3]],
        ls_seq_number: seq,
        ls_checksum: cksum,
        length,
    }))
}

fn parse_hello(header: OspfHeader, input: &[u8]) -> IResult<&[u8], OspfHello> {
    let (input, mask) = take(4usize)(input)?;
    let (input, hello_interval) = be_u16(input)?;
    let (input, options) = be_u8(input)?;
    let (input, priority) = be_u8(input)?;
    let (input, dead_interval) = be_u32(input)?;
    let (input, dr) = take(4usize)(input)?;
    let (input, bdr) = take(4usize)(input)?;

    // Оставшиеся байты — список соседей (по 4 байта каждый)
    let mut neighbors = Vec::new();
    let mut rest = input;
    while rest.len() >= 4 {
        let (r, nb) = take(4usize)(rest)?;
        neighbors.push([nb[0], nb[1], nb[2], nb[3]]);
        rest = r;
    }

    Ok((rest, OspfHello {
        header,
        network_mask: [mask[0], mask[1], mask[2], mask[3]],
        hello_interval,
        options,
        router_priority: priority,
        dead_interval,
        designated_router: [dr[0], dr[1], dr[2], dr[3]],
        backup_dr: [bdr[0], bdr[1], bdr[2], bdr[3]],
        neighbors,
    }))
}

fn parse_dbd(header: OspfHeader, input: &[u8]) -> IResult<&[u8], OspfDbd> {
    let (input, interface_mtu) = be_u16(input)?;
    let (input, options) = be_u8(input)?;
    let (input, flags) = be_u8(input)?;
    let (input, dd_sequence) = be_u32(input)?;

    let mut lsa_headers = Vec::new();
    let mut rest = input;
    while rest.len() >= 20 {
        match parse_lsa_header(rest) {
            Ok((r, lsa)) => {
                lsa_headers.push(lsa);
                rest = r;
            }
            Err(_) => break,
        }
    }

    Ok((rest, OspfDbd { header, interface_mtu, options, flags, dd_sequence, lsa_headers }))
}

fn parse_lsu(header: OspfHeader, input: &[u8]) -> IResult<&[u8], OspfLsu> {
    let (mut input, num_lsas) = be_u32(input)?;

    let mut lsa_headers = Vec::new();
    for _ in 0..num_lsas {
        if input.len() < 20 { break; }
        match parse_lsa_header(input) {
            Ok((rest, lsa)) => {
                // Пропускаем тело LSA (length включает 20-байтный хедер)
                let body_len = (lsa.length as usize).saturating_sub(20);
                lsa_headers.push(lsa);
                if rest.len() >= body_len {
                    input = &rest[body_len..];
                } else {
                    input = &rest[rest.len()..];
                }
            }
            Err(_) => break,
        }
    }

    Ok((input, OspfLsu { header, lsa_headers }))
}

/// Главный entry point — парсим OSPF payload (после IP хедера)
pub fn parse_ospf(input: &[u8]) -> Option<OspfPacket> {
    if input.len() < 24 { return None; }

    let (rest, header) = parse_ospf_header(input).ok()?;

    match header.msg_type {
        OspfType::Hello => {
            parse_hello(header, rest).ok().map(|(_, h)| OspfPacket::Hello(h))
        }
        OspfType::DatabaseDescription => {
            parse_dbd(header, rest).ok().map(|(_, d)| OspfPacket::Dbd(d))
        }
        OspfType::LinkStateUpdate => {
            parse_lsu(header, rest).ok().map(|(_, l)| OspfPacket::Lsu(l))
        }
        _ => Some(OspfPacket::Other(header)),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

pub fn ip_to_str(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
