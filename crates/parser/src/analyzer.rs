// analyzer.rs — сердце тулзы
// Принимает поток OSPF пакетов, строит события и обнаруживает аномалии

use std::collections::HashMap;
use crate::ospf::{OspfPacket, OspfHello, OspfDbd, ip_to_str};
use serde::{Serialize, Deserialize};

/// Временная метка пакета
#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    pub sec: u32,
    pub usec: u32,
}

impl Timestamp {
    pub fn to_f64(&self) -> f64 {
        self.sec as f64 + self.usec as f64 / 1_000_000.0
    }
    pub fn diff_ms(&self, other: &Timestamp) -> f64 {
        (self.to_f64() - other.to_f64()) * 1000.0
    }
}

/// Все события которые мы генерируем
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OspfEvent {
    /// Новый сосед появился
    NeighborDiscovered {
        ts: f64,
        router_id: String,
        src_ip: String,
        area: String,
    },
    /// Сосед пропал (dead interval истёк без Hello)
    NeighborTimeout {
        ts: f64,
        router_id: String,
        last_hello_ts: f64,
        dead_interval: u32,
        elapsed_ms: f64,
    },
    /// Hello interval несовпадение — частая причина adjacency failure
    HelloIntervalMismatch {
        ts: f64,
        router_a: String,
        router_b: String,
        interval_a: u16,
        interval_b: u16,
        src_ip: String,
    },
    /// MTU mismatch — DBD застревает в Exchange state
    MtuMismatch {
        ts: f64,
        router_id: String,
        src_ip: String,
        dst_ip: String,
        mtu: u16,
        expected_mtu: u16,
    },
    /// DR/BDR election — смена designated router
    DrElection {
        ts: f64,
        area: String,
        new_dr: String,
        new_bdr: String,
        router_id: String,
    },
    /// Неожиданная смена DR (уже устоявшаяся сеть)
    DrChange {
        ts: f64,
        area: String,
        old_dr: String,
        new_dr: String,
        router_id: String,
    },
    /// LSA flood — много LSU за короткое время (нестабильность топологии)
    LsaFlood {
        ts: f64,
        router_id: String,
        lsu_count: usize,
        window_ms: f64,
    },
    /// Дублирующийся Router-ID — критическая аномалия
    DuplicateRouterId {
        ts: f64,
        router_id: String,
        ip_a: String,
        ip_b: String,
    },
    /// Authentication mismatch (auth_type разный у соседей)
    AuthMismatch {
        ts: f64,
        router_id: String,
        src_ip: String,
        auth_type: u16,
        expected_auth_type: u16,
    },
    /// Adjacency успешно установлена (DBD exchange завершён — видим двустороннее подтверждение)
    AdjacencyFormed {
        ts: f64,
        router_id: String,
        neighbor_id: String,
        area: String,
    },
    /// Конвергенция — тихий период после флуда
    ConvergenceDetected {
        ts: f64,
        duration_ms: f64,
    },
    /// FSM переход состояния соседа
    StateTransition {
        ts: f64,
        router_id: String,
        from_state: String,
        to_state: String,
    },
}

/// FSM состояния соседа (RFC 2328 Figure 10)
#[derive(Debug, Clone, PartialEq)]
pub enum OspfNbrState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}

impl OspfNbrState {
    pub fn as_str(&self) -> &'static str {
        match self {
            OspfNbrState::Down     => "Down",
            OspfNbrState::Init     => "Init",
            OspfNbrState::TwoWay   => "2-Way",
            OspfNbrState::ExStart  => "ExStart",
            OspfNbrState::Exchange => "Exchange",
            OspfNbrState::Loading  => "Loading",
            OspfNbrState::Full     => "Full",
        }
    }
}

/// Состояние одного OSPF соседа
#[derive(Debug, Clone)]
struct NeighborState {
    router_id: String,
    src_ip: String,
    area: String,
    last_hello: Timestamp,
    dead_interval: u32,
    hello_interval: u16,
    dr: String,
    auth_type: u16,
    dbd_mtu: Option<u16>,
    fsm_state: OspfNbrState,
}

/// Контекст для отслеживания LSU flood
#[derive(Debug, Clone)]
struct LsuTracker {
    window_start: Timestamp,
    count: usize,
}

pub struct Analyzer {
    /// router_id → (src_ip, neighbor state)
    neighbors: HashMap<String, NeighborState>,
    /// src_ip → router_id  (для детекции дублей)
    ip_to_rid: HashMap<String, String>,
    /// первый виденный auth_type в сети
    network_auth_type: Option<u16>,
    /// первый MTU в сети
    network_mtu: Option<u16>,
    /// первый DR в устоявшейся сети
    known_dr: HashMap<String, String>, // area → dr_ip
    /// LSU flood tracker per router
    lsu_tracker: HashMap<String, LsuTracker>,
    /// LSU flood threshold (пакетов за 5 секунд)
    lsu_flood_threshold: usize,
    mtu_mismatch_count: std::collections::HashMap<String, u8>,
    auth_mismatch_seen: std::collections::HashSet<String>,
    adjacency_formed: std::collections::HashSet<String>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            neighbors: HashMap::new(),
            ip_to_rid: HashMap::new(),
            network_auth_type: None,
            network_mtu: None,
            known_dr: HashMap::new(),
            lsu_tracker: HashMap::new(),
            lsu_flood_threshold: 10,
            mtu_mismatch_count: std::collections::HashMap::new(),
            adjacency_formed: std::collections::HashSet::new(),
            auth_mismatch_seen: std::collections::HashSet::new(),
        }
    }

    /// Обрабатываем один пакет, возвращаем список событий
    pub fn process(&mut self, pkt: &OspfPacket, src_ip: &str, dst_ip: &str, ts: Timestamp) -> Vec<OspfEvent> {
        let mut events = Vec::new();

        match pkt {
            OspfPacket::Hello(hello) => {
                self.process_hello(hello, src_ip, ts, &mut events);
            }
            OspfPacket::Dbd(dbd) => {
                self.process_dbd(&dbd.header.router_id_str(), src_ip, dst_ip, dbd.interface_mtu, dbd.flags, ts, &mut events);
                // Детекция adjacency formed: если это не init и не master — Exchange продолжается
                // Упрощённо: видим DBD без I-флага от обеих сторон → adjacency
                if !dbd.is_init() {
                    if let Some(nb) = self.neighbors.get(&dbd.header.router_id_str()) {
                        let area = nb.area.clone();
                        let self_rid = dbd.header.router_id_str();
                        // Ищем другого соседа в той же area как peer
                        let peer_rid = self.neighbors.iter()
                            .find(|(rid, _)| *rid != &self_rid)
                            .map(|(rid, _)| rid.clone())
                            .unwrap_or_else(|| dst_ip.to_string());
                        let pair_key = {
                            let mut pair = vec![self_rid.clone(), peer_rid.clone()];
                            pair.sort();
                            pair.join("-")
                        };
                        if !self.adjacency_formed.contains(&pair_key) {
                            self.adjacency_formed.insert(pair_key);
                            events.push(OspfEvent::AdjacencyFormed {
                                ts: ts.to_f64(),
                                router_id: self_rid,
                                neighbor_id: peer_rid,
                                area,
                            });
                        }
                    }
                }
            }
            OspfPacket::Lsu(lsu) => {
                self.process_lsu(&lsu.header.router_id_str(), ts, &mut events);
            }
            _ => {}
        }

        events
    }

    fn process_hello(&mut self, hello: &OspfHello, src_ip: &str, ts: Timestamp, events: &mut Vec<OspfEvent>) {
        let rid = hello.header.router_id_str();
        let area = hello.header.area_id_str();
        let dr = hello.dr_str();
        let auth_type = hello.header.auth_type;

        // Детекция дублирующегося Router-ID
        if let Some(existing_ip) = self.ip_to_rid.get(&rid) {
            if existing_ip != src_ip && !self.auth_mismatch_seen.contains(&format!("dup_{}", rid)) {
                self.auth_mismatch_seen.insert(format!("dup_{}", rid));
                events.push(OspfEvent::DuplicateRouterId {
                    ts: ts.to_f64(),
                    router_id: rid.clone(),
                    ip_a: existing_ip.clone(),
                    ip_b: src_ip.to_string(),
                });
            }
        }
        self.ip_to_rid.insert(rid.clone(), src_ip.to_string());

        // Auth type детекция
        match self.network_auth_type {
            None => {
                self.network_auth_type = Some(auth_type);
            }
            Some(expected) if expected != auth_type && !self.auth_mismatch_seen.contains(&rid) => {
                self.auth_mismatch_seen.insert(rid.clone());
                events.push(OspfEvent::AuthMismatch {
                    ts: ts.to_f64(),
                    router_id: rid.clone(),
                    src_ip: src_ip.to_string(),
                    auth_type,
                    expected_auth_type: expected,
                });
            }
            _ => {}
        }

        match self.neighbors.get(&rid) {
            None => {
                // Проверяем hello interval против уже известных соседей
                for (_, existing_nb) in &self.neighbors {
                    if existing_nb.hello_interval != hello.hello_interval {
                        events.push(OspfEvent::HelloIntervalMismatch {
                            ts: ts.to_f64(),
                            router_a: rid.clone(),
                            router_b: existing_nb.router_id.clone(),
                            interval_a: hello.hello_interval,
                            interval_b: existing_nb.hello_interval,
                            src_ip: src_ip.to_string(),
                        });
                    }
                }
                // Новый сосед
                events.push(OspfEvent::NeighborDiscovered {
                    ts: ts.to_f64(),
                    router_id: rid.clone(),
                    src_ip: src_ip.to_string(),
                    area: area.clone(),
                });

                self.neighbors.insert(rid.clone(), NeighborState {
                    router_id: rid.clone(),
                    src_ip: src_ip.to_string(),
                    area,
                    last_hello: ts,
                    dead_interval: hello.dead_interval,
                    hello_interval: hello.hello_interval,
                    dr: dr.clone(),
                    auth_type,
                    dbd_mtu: None,
                    fsm_state: OspfNbrState::Init,
                });
            }
            Some(existing) => {
                // Hello interval mismatch
                if existing.hello_interval != hello.hello_interval {
                    events.push(OspfEvent::HelloIntervalMismatch {
                        ts: ts.to_f64(),
                        router_a: rid.clone(),
                        router_b: existing.router_id.clone(),
                        interval_a: hello.hello_interval,
                        interval_b: existing.hello_interval,
                        src_ip: src_ip.to_string(),
                    });
                }

                // DR change detection
                let area_key = hello.header.area_id_str();
                if let Some(known) = self.known_dr.get(&area_key) {
                    if *known != dr && dr != "0.0.0.0" && !known.is_empty() {
                        events.push(OspfEvent::DrChange {
                            ts: ts.to_f64(),
                            area: area_key.clone(),
                            old_dr: known.clone(),
                            new_dr: dr.clone(),
                            router_id: rid.clone(),
                        });
                    }
                } else if dr != "0.0.0.0" {
                    events.push(OspfEvent::DrElection {
                        ts: ts.to_f64(),
                        area: area_key.clone(),
                        new_dr: dr.clone(),
                        new_bdr: hello.bdr_str(),
                        router_id: rid.clone(),
                    });
                }

                if dr != "0.0.0.0" {
                    self.known_dr.insert(area_key, dr.clone());
                }

                // FSM: если в списке соседей есть наш own RID — переходим в TwoWay
                // Упрощение: считаем что any neighbor entry = TwoWay достижимо
                if let Some(nb) = self.neighbors.get_mut(&rid) {
                    nb.last_hello = ts;
                    nb.dr = dr;
                    // TwoWay: видим соседа в его Hello neighbor list
                    if nb.fsm_state == OspfNbrState::Init {
                        let old_state = nb.fsm_state.as_str().to_string();
                        nb.fsm_state = OspfNbrState::TwoWay;
                        events.push(OspfEvent::StateTransition {
                            ts: ts.to_f64(),
                            router_id: rid.clone(),
                            from_state: old_state,
                            to_state: "2-Way".to_string(),
                        });
                    }
                }
            }
        }
    }

    fn process_dbd(&mut self, rid: &str, src_ip: &str, dst_ip: &str, mtu: u16, flags: u8, ts: Timestamp, events: &mut Vec<OspfEvent>) {
        // FSM переходы по DBD флагам
        if let Some(nb) = self.neighbors.get_mut(rid) {
            let is_init = flags & 0x04 != 0;
            let new_state = if is_init {
                Some(OspfNbrState::ExStart)
            } else if nb.fsm_state == OspfNbrState::ExStart {
                Some(OspfNbrState::Exchange)
            } else {
                None
            };
            if let Some(next) = new_state {
                if nb.fsm_state != next {
                    let from = nb.fsm_state.as_str().to_string();
                    let to   = next.as_str().to_string();
                    nb.fsm_state = next;
                    events.push(OspfEvent::StateTransition {
                        ts: ts.to_f64(),
                        router_id: rid.to_string(),
                        from_state: from,
                        to_state: to,
                    });
                }
            }
        }
        match self.network_mtu {
            None => {
                self.network_mtu = Some(mtu);
                if let Some(nb) = self.neighbors.get_mut(rid) {
                    nb.dbd_mtu = Some(mtu);
                }
            }
            Some(expected) if expected != mtu && mtu != 0 => {
                let count = self.mtu_mismatch_count.entry(rid.to_string()).or_insert(0);
                *count += 1;
                if *count == 1 {
                events.push(OspfEvent::MtuMismatch {
                    ts: ts.to_f64(),
                    router_id: rid.to_string(),
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    mtu,
                    expected_mtu: expected,
                });
                } // end if count == 1
            }
            _ => {}
        }
    }

    fn process_lsu(&mut self, rid: &str, ts: Timestamp, events: &mut Vec<OspfEvent>) {
        // FSM: Exchange → Loading при первом LSU
        if let Some(nb) = self.neighbors.get_mut(rid) {
            if nb.fsm_state == OspfNbrState::Exchange {
                let from = nb.fsm_state.as_str().to_string();
                nb.fsm_state = OspfNbrState::Loading;
                events.push(OspfEvent::StateTransition {
                    ts: ts.to_f64(),
                    router_id: rid.to_string(),
                    from_state: from,
                    to_state: "Loading".to_string(),
                });
            }
        }
        let tracker = self.lsu_tracker.entry(rid.to_string()).or_insert(LsuTracker {
            window_start: ts,
            count: 0,
        });

        let elapsed = ts.diff_ms(&tracker.window_start);

        if elapsed > 5000.0 {
            // Новое окно
            tracker.window_start = ts;
            tracker.count = 1;
        } else {
            tracker.count += 1;
            if tracker.count == self.lsu_flood_threshold {
                events.push(OspfEvent::LsaFlood {
                    ts: ts.to_f64(),
                    router_id: rid.to_string(),
                    lsu_count: tracker.count,
                    window_ms: elapsed,
                });
            }
        }
    }

    /// Возвращает количество MTU mismatch DBD пакетов per router_id
    pub fn mtu_mismatch_counts(&self) -> &std::collections::HashMap<String, u8> {
        &self.mtu_mismatch_count
    }

    /// Вызываем в конце — проверяем таймауты соседей
    pub fn finalize(&mut self, last_ts: Timestamp) -> Vec<OspfEvent> {
        let mut events = Vec::new();

        for (rid, nb) in &self.neighbors {
            let elapsed = last_ts.diff_ms(&nb.last_hello);
            let dead_ms = nb.dead_interval as f64 * 1000.0;

            if elapsed > dead_ms {
                events.push(OspfEvent::NeighborTimeout {
                    ts: last_ts.to_f64(),
                    router_id: rid.clone(),
                    last_hello_ts: nb.last_hello.to_f64(),
                    dead_interval: nb.dead_interval,
                    elapsed_ms: elapsed,
                });
            }
        }

        events
    }
}

/// Итоговый отчёт
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub total_packets: usize,
    pub ospf_packets: usize,
    pub duration_sec: f64,
    pub events: Vec<TimedEvent>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimedEvent {
    pub ts: f64,
    pub event: OspfEvent,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub routers_seen: usize,
    pub anomalies: usize,
    pub neighbor_timeouts: usize,
    pub mtu_mismatches: usize,
    pub duplicate_rids: usize,
    pub dr_changes: usize,
}

pub fn classify_event(event: &OspfEvent) -> Severity {
    match event {
        OspfEvent::DuplicateRouterId { .. } => Severity::Critical,
        OspfEvent::MtuMismatch { .. } => Severity::Critical,
        OspfEvent::AuthMismatch { .. } => Severity::Critical,
        OspfEvent::NeighborTimeout { .. } => Severity::Warning,
        OspfEvent::DrChange { .. } => Severity::Warning,
        OspfEvent::HelloIntervalMismatch { .. } => Severity::Warning,
        OspfEvent::LsaFlood { .. } => Severity::Warning,
        _ => Severity::Info,
    }
}
