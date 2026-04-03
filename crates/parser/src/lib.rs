#![allow(dead_code, unused_imports, unused_variables)]

mod pcap;
mod net;
mod ospf;
mod analyzer;
mod root_cause;

use wasm_bindgen::prelude::*;
use analyzer::{Analyzer, AnalysisReport, TimedEvent, ReportSummary, classify_event};
use net::PROTO_OSPF;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub fn analyze_pcap(data: &[u8]) -> Result<JsValue, JsValue> {
    let (_, packets) = pcap::iter_packets(data)
        .map_err(|e| JsValue::from_str(&e))?;

    console_log!("PCAP parsed: {} packets", packets.len());

    let mut analyzer = Analyzer::new();
    let mut events: Vec<TimedEvent> = Vec::new();
    let mut ospf_count = 0usize;
    let mut last_ts = analyzer::Timestamp { sec: 0, usec: 0 };

    let first_ts = packets.first()
        .map(|p| p.ts_sec as f64 + p.ts_usec as f64 / 1e6)
        .unwrap_or(0.0);

    for pkt in &packets {
        let ts = analyzer::Timestamp { sec: pkt.ts_sec, usec: pkt.ts_usec };
        last_ts = ts;

        let Some((ip, payload)) = net::extract_ip(pkt.data) else { continue };
        if ip.protocol != PROTO_OSPF { continue; }

        let Some(ospf_pkt) = ospf::parse_ospf(payload) else { continue };
        ospf_count += 1;

        let src = ip.src_str();
        let dst = ip.dst_str();

        let new_events = analyzer.process(&ospf_pkt, &src, &dst, ts);
        for ev in new_events {
            let severity = classify_event(&ev);
            events.push(TimedEvent { ts: ts.to_f64(), event: ev, severity });
        }
    }

    let final_events = analyzer.finalize(last_ts);
    for ev in final_events {
        let severity = classify_event(&ev);
        events.push(TimedEvent { ts: last_ts.to_f64(), event: ev, severity });
    }

    // Root cause correlation
    let mtu_counts = analyzer.mtu_mismatch_counts().clone();
    let root_cause_report = root_cause::correlate(&events, &mtu_counts);

    let anomalies        = events.iter().filter(|e| matches!(e.severity, analyzer::Severity::Warning | analyzer::Severity::Critical)).count();
    let neighbor_timeouts = events.iter().filter(|e| matches!(e.event, analyzer::OspfEvent::NeighborTimeout { .. })).count();
    let mtu_mismatches   = events.iter().filter(|e| matches!(e.event, analyzer::OspfEvent::MtuMismatch { .. })).count();
    let duplicate_rids   = events.iter().filter(|e| matches!(e.event, analyzer::OspfEvent::DuplicateRouterId { .. })).count();
    let dr_changes       = events.iter().filter(|e| matches!(e.event, analyzer::OspfEvent::DrChange { .. })).count();

    let routers_seen = {
        let mut rids = std::collections::HashSet::new();
        for te in &events {
            if let analyzer::OspfEvent::NeighborDiscovered { router_id, .. } = &te.event {
                rids.insert(router_id.clone());
            }
        }
        rids.len()
    };

    let report = FullReport {
        total_packets: packets.len(),
        ospf_packets: ospf_count,
        duration_sec: last_ts.to_f64() - first_ts,
        events,
        summary: ReportSummary {
            routers_seen,
            anomalies,
            neighbor_timeouts,
            mtu_mismatches,
            duplicate_rids,
            dr_changes,
        },
        root_cause: root_cause_report,
    };

    serde_wasm_bindgen::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Расширенный отчёт с root cause
#[derive(serde::Serialize)]
struct FullReport {
    total_packets: usize,
    ospf_packets: usize,
    duration_sec: f64,
    events: Vec<TimedEvent>,
    summary: ReportSummary,
    root_cause: root_cause::RootCauseReport,
}

pub use analyzer::Timestamp;
