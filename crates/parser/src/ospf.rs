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

impl std::fmt::Display for RouterLinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RouterLinkType::PointToPoint   => write!(f, "p2p"),
            RouterLinkType::TransitNetwork => write!(f, "transit"),
            RouterLinkType::StubNetwork    => write!(f, "stub"),
            RouterLinkType::VirtualLink    => write!(f, "virtual"),
            RouterLinkType::Unknown(n)     => write!(f, "unknown({})", n),
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub router_lsas: Vec<RouterLsa>,
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

/// LSAck — список LSA хедеров подтверждений
#[derive(Debug, Clone)]
pub struct OspfLsAck {
    pub header: OspfHeader,
    pub lsa_headers: Vec<LsaHeader>,
}

/// LSR — список запросов конкретных LSA
#[derive(Debug, Clone)]
pub struct LsRequest {
    pub ls_type: u32,
    pub link_state_id: [u8; 4],
    pub advertising_router: [u8; 4],
}

#[derive(Debug, Clone)]
pub struct OspfLsr {
    pub header: OspfHeader,
    pub requests: Vec<LsRequest>,
}

/// Unified enum — результат парсинга
#[derive(Debug, Clone)]
pub enum OspfPacket {
    Hello(OspfHello),
    Dbd(OspfDbd),
    Lsu(OspfLsu),
    LsAck(OspfLsAck),
    Lsr(OspfLsr),
    Other(OspfHeader),
}

impl OspfPacket {
    pub fn header(&self) -> &OspfHeader {
        match self {
            OspfPacket::Hello(h) => &h.header,
            OspfPacket::Dbd(d) => &d.header,
            OspfPacket::Lsu(l) => &l.header,
            OspfPacket::LsAck(a) => &a.header,
            OspfPacket::Lsr(r) => &r.header,
            OspfPacket::Other(h) => h,
        }
    }
}

/// Тип линка в Router-LSA (RFC 2328 §12.4.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RouterLinkType {
    PointToPoint,    // 1 — p2p линк к другому роутеру
    TransitNetwork,  // 2 — линк к broadcast сети (через DR)
    StubNetwork,     // 3 — stub сеть (loopback, etc)
    VirtualLink,     // 4 — virtual link
    Unknown(u8),
}

impl From<u8> for RouterLinkType {
    fn from(v: u8) -> Self {
        match v {
            1 => RouterLinkType::PointToPoint,
            2 => RouterLinkType::TransitNetwork,
            3 => RouterLinkType::StubNetwork,
            4 => RouterLinkType::VirtualLink,
            n => RouterLinkType::Unknown(n),
        }
    }
}

/// Один линк из Router-LSA
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouterLink {
    pub link_id: [u8; 4],    // Router-ID соседа (p2p) или IP DR (transit)
    pub link_data: [u8; 4],  // IP интерфейса или subnet mask
    pub link_type: RouterLinkType,
    pub metric: u16,
}

impl RouterLink {
    pub fn link_id_str(&self) -> String {
        crate::ospf::ip_to_str(&self.link_id)
    }
    pub fn link_data_str(&self) -> String {
        crate::ospf::ip_to_str(&self.link_data)
    }
}

/// Распарсенное тело Router-LSA
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouterLsa {
    pub header: LsaHeader,
    pub flags: u8,
    pub links: Vec<RouterLink>,
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

/// Парсим тело Router-LSA (type 1)
/// Структура: flags(1) + reserved(1) + num_links(2) + N * link(12)
pub fn parse_router_lsa_body(header: LsaHeader, body: &[u8]) -> Option<RouterLsa> {
    if body.len() < 4 { return None; }
    let flags = body[0];
    // body[1] reserved
    let num_links = u16::from_be_bytes([body[2], body[3]]) as usize;
    let mut links = Vec::new();
    let mut pos = 4usize;

    for _ in 0..num_links {
        // Каждый линк: link_id(4) + link_data(4) + type(1) + num_tos(1) + metric(2) + TOS data
        if pos + 12 > body.len() { break; }
        let link_id   = [body[pos], body[pos+1], body[pos+2], body[pos+3]];
        let link_data = [body[pos+4], body[pos+5], body[pos+6], body[pos+7]];
        let link_type = RouterLinkType::from(body[pos+8]);
        let num_tos   = body[pos+9] as usize;
        let metric    = u16::from_be_bytes([body[pos+10], body[pos+11]]);
        pos += 12 + num_tos * 4; // пропускаем TOS data

        links.push(RouterLink { link_id, link_data, link_type, metric });
    }

    Some(RouterLsa { header, flags, links })
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
    let mut router_lsas = Vec::new();

    for _ in 0..num_lsas {
        if input.len() < 20 { break; }
        match parse_lsa_header(input) {
            Ok((rest, lsa)) => {
                let body_len = (lsa.length as usize).saturating_sub(20);
                let body = if rest.len() >= body_len { &rest[..body_len] } else { rest };

                // Парсим тело Router-LSA (type 1)
                if lsa.ls_type == 1 {
                    if let Some(rlsa) = parse_router_lsa_body(lsa.clone(), body) {
                        router_lsas.push(rlsa);
                    }
                }

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

    Ok((input, OspfLsu { header, lsa_headers, router_lsas }))
}

fn parse_lsack(header: OspfHeader, input: &[u8]) -> IResult<&[u8], OspfLsAck> {
    let mut lsa_headers = Vec::new();
    let mut rest = input;
    while rest.len() >= 20 {
        match parse_lsa_header(rest) {
            Ok((r, lsa)) => { lsa_headers.push(lsa); rest = r; }
            Err(_) => break,
        }
    }
    Ok((rest, OspfLsAck { header, lsa_headers }))
}

fn parse_lsr(header: OspfHeader, input: &[u8]) -> IResult<&[u8], OspfLsr> {
    let mut requests = Vec::new();
    let mut rest = input;
    while rest.len() >= 12 {
        let ls_type = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let link_state_id = [rest[4], rest[5], rest[6], rest[7]];
        let adv_r = [rest[8], rest[9], rest[10], rest[11]];
        requests.push(LsRequest { ls_type, link_state_id, advertising_router: adv_r });
        rest = &rest[12..];
    }
    Ok((rest, OspfLsr { header, requests }))
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
        OspfType::LinkStateAck => {
            parse_lsack(header, rest).ok().map(|(_, a)| OspfPacket::LsAck(a))
        }
        OspfType::LinkStateRequest => {
            parse_lsr(header, rest).ok().map(|(_, r)| OspfPacket::Lsr(r))
        }
        _ => Some(OspfPacket::Other(header)),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

pub fn ip_to_str(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal valid OSPF header (24 bytes)
    fn ospf_header(msg_type: u8, router_id: [u8; 4], area_id: [u8; 4]) -> Vec<u8> {
        let mut h = Vec::new();
        h.push(2u8);                                      // version
        h.push(msg_type);                                 // type
        h.extend_from_slice(&0u16.to_be_bytes());         // packet_len (placeholder)
        h.extend_from_slice(&router_id);
        h.extend_from_slice(&area_id);
        h.extend_from_slice(&0u16.to_be_bytes());         // checksum
        h.extend_from_slice(&0u16.to_be_bytes());         // auth_type
        h.extend_from_slice(&[0u8; 8]);                   // auth_data
        h
    }

    fn hello_body(neighbors: &[[u8; 4]]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[255, 255, 255, 0]);         // network_mask
        b.extend_from_slice(&10u16.to_be_bytes());        // hello_interval
        b.push(0x02);                                     // options
        b.push(1u8);                                      // router_priority
        b.extend_from_slice(&40u32.to_be_bytes());        // dead_interval
        b.extend_from_slice(&[192, 168, 1, 1]);           // DR
        b.extend_from_slice(&[192, 168, 1, 2]);           // BDR
        for nb in neighbors {
            b.extend_from_slice(nb);
        }
        b
    }

    fn dbd_body(mtu: u16, flags: u8, seq: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&mtu.to_be_bytes());
        b.push(0x02); // options
        b.push(flags);
        b.extend_from_slice(&seq.to_be_bytes());
        b
    }

    fn lsa_header_bytes(ls_type: u8, advertising_router: [u8; 4]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&0u16.to_be_bytes());         // ls_age
        h.push(0x02);                                     // options
        h.push(ls_type);
        h.extend_from_slice(&[10, 0, 0, 1]);              // link_state_id
        h.extend_from_slice(&advertising_router);
        h.extend_from_slice(&1u32.to_be_bytes());         // seq
        h.extend_from_slice(&0u16.to_be_bytes());         // checksum
        h.extend_from_slice(&36u16.to_be_bytes());        // length
        h
    }

    const RID_A: [u8; 4] = [1, 1, 1, 1];
    const RID_B: [u8; 4] = [2, 2, 2, 2];
    const AREA0: [u8; 4] = [0, 0, 0, 0];

    // ── parse_ospf ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_hello_basic() {
        let mut pkt = ospf_header(1, RID_A, AREA0);
        pkt.extend(hello_body(&[]));
        let result = parse_ospf(&pkt).expect("should parse");
        match result {
            OspfPacket::Hello(h) => {
                assert_eq!(h.header.router_id, RID_A);
                assert_eq!(h.hello_interval, 10);
                assert_eq!(h.dead_interval, 40);
                assert_eq!(h.neighbors.len(), 0);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn test_parse_hello_with_neighbors() {
        let mut pkt = ospf_header(1, RID_A, AREA0);
        pkt.extend(hello_body(&[RID_B, [3, 3, 3, 3]]));
        match parse_ospf(&pkt).unwrap() {
            OspfPacket::Hello(h) => {
                assert_eq!(h.neighbors.len(), 2);
                assert_eq!(h.neighbors[0], RID_B);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[test]
    fn test_parse_dbd_init_flag() {
        let mut pkt = ospf_header(2, RID_A, AREA0);
        pkt.extend(dbd_body(1500, 0x07, 1000)); // flags: I=1 M=1 MS=1
        match parse_ospf(&pkt).unwrap() {
            OspfPacket::Dbd(d) => {
                assert_eq!(d.interface_mtu, 1500);
                assert!(d.is_init());
                assert!(d.is_master());
                assert!(d.is_more());
                assert_eq!(d.dd_sequence, 1000);
            }
            _ => panic!("expected DBD"),
        }
    }

    #[test]
    fn test_parse_dbd_mtu_mismatch_detection() {
        let mut pkt_a = ospf_header(2, RID_A, AREA0);
        pkt_a.extend(dbd_body(1500, 0x04, 1));
        let mut pkt_b = ospf_header(2, RID_B, AREA0);
        pkt_b.extend(dbd_body(1400, 0x04, 1));

        let dbd_a = match parse_ospf(&pkt_a).unwrap() { OspfPacket::Dbd(d) => d, _ => panic!() };
        let dbd_b = match parse_ospf(&pkt_b).unwrap() { OspfPacket::Dbd(d) => d, _ => panic!() };

        assert_ne!(dbd_a.interface_mtu, dbd_b.interface_mtu);
    }

    #[test]
    fn test_parse_lsack_with_headers() {
        let mut pkt = ospf_header(5, RID_A, AREA0);
        pkt.extend(lsa_header_bytes(1, RID_A));
        pkt.extend(lsa_header_bytes(2, RID_B));
        match parse_ospf(&pkt).unwrap() {
            OspfPacket::LsAck(a) => assert_eq!(a.lsa_headers.len(), 2),
            _ => panic!("expected LSAck"),
        }
    }

    #[test]
    fn test_parse_lsr() {
        let mut pkt = ospf_header(3, RID_A, AREA0);
        // LSR entry: ls_type(4) + link_state_id(4) + adv_router(4)
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&RID_B);
        match parse_ospf(&pkt).unwrap() {
            OspfPacket::Lsr(r) => {
                assert_eq!(r.requests.len(), 1);
                assert_eq!(r.requests[0].ls_type, 1);
            }
            _ => panic!("expected LSR"),
        }
    }

    #[test]
    fn test_too_short_returns_none() {
        assert!(parse_ospf(&vec![0u8; 20]).is_none());
    }

    #[test]
    fn test_unknown_type_returns_other() {
        let pkt = ospf_header(99, RID_A, AREA0);
        match parse_ospf(&pkt).unwrap() {
            OspfPacket::Other(h) => assert!(matches!(h.msg_type, OspfType::Unknown(99))),
            _ => panic!("expected Other"),
        }
    }

    // ── OspfHeader helpers ────────────────────────────────────────────────────

    #[test]
    fn test_router_id_str() {
        let pkt = ospf_header(1, [10, 0, 0, 1], AREA0);
        let mut body = hello_body(&[]);
        let mut full = pkt; full.extend(body);
        match parse_ospf(&full).unwrap() {
            OspfPacket::Hello(h) => assert_eq!(h.header.router_id_str(), "10.0.0.1"),
            _ => panic!(),
        }
    }

    #[test]
    fn test_area_id_str() {
        let pkt = ospf_header(1, RID_A, [0, 0, 0, 1]);
        let mut full = pkt; full.extend(hello_body(&[]));
        match parse_ospf(&full).unwrap() {
            OspfPacket::Hello(h) => assert_eq!(h.header.area_id_str(), "0.0.0.1"),
            _ => panic!(),
        }
    }

    // ── OspfType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_ospf_type_from_u8() {
        assert_eq!(OspfType::from(1), OspfType::Hello);
        assert_eq!(OspfType::from(2), OspfType::DatabaseDescription);
        assert_eq!(OspfType::from(3), OspfType::LinkStateRequest);
        assert_eq!(OspfType::from(4), OspfType::LinkStateUpdate);
        assert_eq!(OspfType::from(5), OspfType::LinkStateAck);
        assert!(matches!(OspfType::from(99), OspfType::Unknown(99)));
    }

    #[test]
    fn test_ospf_type_display() {
        assert_eq!(format!("{}", OspfType::Hello), "Hello");
        assert_eq!(format!("{}", OspfType::DatabaseDescription), "DBD");
        assert_eq!(format!("{}", OspfType::Unknown(7)), "Unknown(7)");
    }

    // ── LsaHeader ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lsa_header_type_str() {
        let h_bytes = lsa_header_bytes(1, RID_A);
        let (_, lsa) = super::parse_lsa_header(&h_bytes).unwrap();
        assert_eq!(lsa.ls_type_str(), "Router-LSA");
        assert_eq!(lsa.advertising_router_str(), "1.1.1.1");
    }

    #[test]
    fn test_lsa_type_strings() {
        for (t, expected) in [
            (1u8, "Router-LSA"),
            (2,   "Network-LSA"),
            (3,   "Summary-LSA (Network)"),
            (5,   "AS-External-LSA"),
        ] {
            let h_bytes = lsa_header_bytes(t, RID_A);
            let (_, lsa) = super::parse_lsa_header(&h_bytes).unwrap();
            assert_eq!(lsa.ls_type_str(), expected);
        }
    }

    // ── OspfDbd flags ─────────────────────────────────────────────────────────

    #[test]
    fn test_dbd_flags() {
        let mut pkt = ospf_header(2, RID_A, AREA0);
        pkt.extend(dbd_body(1500, 0x00, 42));
        match parse_ospf(&pkt).unwrap() {
            OspfPacket::Dbd(d) => {
                assert!(!d.is_init());
                assert!(!d.is_master());
                assert!(!d.is_more());
            }
            _ => panic!(),
        }
    }

    // ── Router-LSA body ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_router_lsa_body_single_link() {
        let header = LsaHeader {
            ls_age: 0, options: 0, ls_type: 1,
            link_state_id: [10, 0, 0, 1],
            advertising_router: RID_A,
            ls_seq_number: 1, ls_checksum: 0, length: 36,
        };
        let mut body = vec![0u8, 0u8, 0u8, 1u8]; // flags=0, reserved=0, num_links=1
        body.extend_from_slice(&[2, 2, 2, 2]);    // link_id
        body.extend_from_slice(&[10, 0, 0, 1]);   // link_data
        body.push(1);                             // type: p2p
        body.push(0);                             // num_tos
        body.extend_from_slice(&10u16.to_be_bytes()); // metric
        let lsa = parse_router_lsa_body(header, &body).expect("should parse");
        assert_eq!(lsa.links.len(), 1);
        assert_eq!(lsa.links[0].metric, 10);
        assert!(matches!(lsa.links[0].link_type, RouterLinkType::PointToPoint));
        assert_eq!(lsa.links[0].link_id_str(), "2.2.2.2");
    }

    #[test]
    fn test_parse_router_lsa_body_too_short() {
        let header = LsaHeader {
            ls_age: 0, options: 0, ls_type: 1,
            link_state_id: [0;4], advertising_router: RID_A,
            ls_seq_number: 0, ls_checksum: 0, length: 20,
        };
        assert!(parse_router_lsa_body(header, &[0u8; 2]).is_none());
    }

    // ── RouterLinkType ────────────────────────────────────────────────────────

    #[test]
    fn test_router_link_type_from_u8() {
        assert!(matches!(RouterLinkType::from(1), RouterLinkType::PointToPoint));
        assert!(matches!(RouterLinkType::from(2), RouterLinkType::TransitNetwork));
        assert!(matches!(RouterLinkType::from(3), RouterLinkType::StubNetwork));
        assert!(matches!(RouterLinkType::from(4), RouterLinkType::VirtualLink));
        assert!(matches!(RouterLinkType::from(99), RouterLinkType::Unknown(99)));
    }

    #[test]
    fn test_router_link_type_display() {
        assert_eq!(format!("{}", RouterLinkType::PointToPoint), "p2p");
        assert_eq!(format!("{}", RouterLinkType::TransitNetwork), "transit");
        assert_eq!(format!("{}", RouterLinkType::StubNetwork), "stub");
    }

    // ── ip_to_str ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ip_to_str() {
        assert_eq!(ip_to_str(&[10, 0, 0, 1]),       "10.0.0.1");
        assert_eq!(ip_to_str(&[0, 0, 0, 0]),         "0.0.0.0");
        assert_eq!(ip_to_str(&[255, 255, 255, 255]), "255.255.255.255");
    }
}
