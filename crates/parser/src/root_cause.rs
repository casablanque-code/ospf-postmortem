// root_cause.rs — корреляция событий в причинно-следственные цепочки
//
// Принцип: берём плоский список TimedEvent, ищем паттерны,
// строим RootCauseReport с primary issue + impact + secondary effects.

use serde::{Serialize, Deserialize};
use crate::analyzer::{TimedEvent, OspfEvent, Severity};

/// Типы первопричин — то что реально сломало сеть
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RootCauseKind {
    MtuMismatch,
    HelloTimerMismatch,
    DuplicateRouterId,
    AuthenticationMismatch,
    NeighborFlapping,
    DrInstability,
    TopologyInstability,
    Clean, // всё хорошо
}

impl RootCauseKind {
    pub fn title(&self) -> &'static str {
        match self {
            RootCauseKind::MtuMismatch           => "MTU Mismatch",
            RootCauseKind::HelloTimerMismatch     => "Hello/Dead Timer Mismatch",
            RootCauseKind::DuplicateRouterId      => "Duplicate Router-ID",
            RootCauseKind::AuthenticationMismatch => "Authentication Mismatch",
            RootCauseKind::NeighborFlapping       => "Neighbor Flapping",
            RootCauseKind::DrInstability          => "DR/BDR Instability",
            RootCauseKind::TopologyInstability    => "Topology Instability",
            RootCauseKind::Clean                  => "No Issues Detected",
        }
    }
}

/// Одна первопричина с цепочкой следствий
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub kind: RootCauseKind,
    pub severity: RootCauseSeverity,

    /// Что случилось — коротко, одна строка
    pub headline: String,

    /// Почему это плохо — операциональный контекст
    pub impact: String,

    /// Что надо проверить/сделать
    pub remediation: String,

    /// Какие события из timeline это подтверждают
    pub evidence: Vec<EvidenceRef>,

    /// Вторичные эффекты порождённые этой причиной
    pub secondary_effects: Vec<String>,

    /// Роутеры/IP вовлечённые в инцидент
    pub affected_routers: Vec<String>,

    /// Временной диапазон
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RootCauseSeverity {
    Info,
    Warning,
    Critical,
}

/// Ссылка на конкретное событие в timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub ts: f64,
    pub event_type: String,
    pub description: String,
}

/// Итоговый root cause отчёт
#[derive(Debug, Serialize, Deserialize)]
pub struct RootCauseReport {
    /// Упорядочены по severity desc
    pub causes: Vec<RootCause>,

    /// Одна строка — общий вердикт
    pub verdict: String,

    /// Была ли сеть стабильна в конце capture
    pub converged: bool,

    /// Рекомендуемый порядок действий
    pub action_plan: Vec<String>,
}

// ── Correlator ───────────────────────────────────────────────────────────────

pub fn correlate(events: &[TimedEvent]) -> RootCauseReport {
    let mut causes: Vec<RootCause> = Vec::new();

    // Каждый детектор независим — смотрит на весь список событий
    if let Some(c) = detect_mtu_mismatch(events)         { causes.push(c); }
    if let Some(c) = detect_hello_mismatch(events)       { causes.push(c); }
    if let Some(c) = detect_duplicate_rid(events)        { causes.push(c); }
    if let Some(c) = detect_auth_mismatch(events)        { causes.push(c); }
    if let Some(c) = detect_neighbor_flapping(events)    { causes.push(c); }
    if let Some(c) = detect_dr_instability(events)       { causes.push(c); }
    if let Some(c) = detect_topology_instability(events) { causes.push(c); }

    // Сортируем: Critical → Warning → Info
    causes.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

    let converged = assess_convergence(events);
    let verdict   = build_verdict(&causes, converged);
    let action_plan = build_action_plan(&causes);

    if causes.is_empty() {
        causes.push(RootCause {
            kind: RootCauseKind::Clean,
            severity: RootCauseSeverity::Info,
            headline: "Network operating normally".into(),
            impact: "All adjacencies formed without anomalies. No timer mismatches, MTU issues, or instability detected.".into(),
            remediation: "No action required.".into(),
            evidence: Vec::new(),
            secondary_effects: Vec::new(),
            affected_routers: Vec::new(),
            first_seen: 0.0,
            last_seen: 0.0,
        });
    }

    RootCauseReport { causes, verdict, converged, action_plan }
}

// ── Детекторы ─────────────────────────────────────────────────────────────────

fn detect_mtu_mismatch(events: &[TimedEvent]) -> Option<RootCause> {
    let mismatches: Vec<_> = events.iter().filter(|e|
        matches!(e.event, OspfEvent::MtuMismatch { .. })
    ).collect();

    if mismatches.is_empty() { return None; }

    let mut routers = Vec::new();
    let mut evidence = Vec::new();

    for te in &mismatches {
        if let OspfEvent::MtuMismatch { router_id, src_ip, mtu, expected_mtu, .. } = &te.event {
            routers.push(router_id.clone());
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "MtuMismatch".into(),
                description: format!("{} advertises MTU {} (expected {})", router_id, mtu, expected_mtu),
            });
        }
    }

    // Ищем смежные события — если есть таймаут соседа после mismatch, это secondary effect
    let mut secondary = Vec::new();
    let first_mismatch_ts = mismatches[0].ts;

    let timeouts_after: Vec<_> = events.iter().filter(|e|
        e.ts >= first_mismatch_ts &&
        matches!(e.event, OspfEvent::NeighborTimeout { .. })
    ).collect();

    if !timeouts_after.is_empty() {
        secondary.push(format!(
            "{} neighbor timeout(s) followed — adjacency never stabilized",
            timeouts_after.len()
        ));
        for te in &timeouts_after {
            if let OspfEvent::NeighborTimeout { router_id, .. } = &te.event {
                evidence.push(EvidenceRef {
                    ts: te.ts,
                    event_type: "NeighborTimeout".into(),
                    description: format!("Neighbor {} timed out after MTU mismatch", router_id),
                });
            }
        }
    }

    // Если adjacency вообще не сформировалась
    let adj_formed = events.iter().any(|e| matches!(e.event, OspfEvent::AdjacencyFormed { .. }));
    if !adj_formed {
        secondary.push("Adjacency never formed — DBD exchange stuck in ExStart/Exchange state".into());
    }

    Some(RootCause {
        kind: RootCauseKind::MtuMismatch,
        severity: RootCauseSeverity::Critical,
        headline: format!("MTU mismatch on {} — DBD exchange cannot complete", routers.join(", ")),
        impact: "OSPF adjacency is stuck in ExStart or Exchange state. Routers exchange DBD packets indefinitely but never reach Full state. This is a silent failure — no error message, just a hung state machine.".into(),
        remediation: "Verify interface MTU with `show interface` on both sides. Either set matching MTU or use `ip ospf mtu-ignore` as a workaround (not recommended in production).".into(),
        evidence,
        secondary_effects: secondary,
        affected_routers: routers,
        first_seen: mismatches[0].ts,
        last_seen: mismatches.last().unwrap().ts,
    })
}

fn detect_hello_mismatch(events: &[TimedEvent]) -> Option<RootCause> {
    let mismatches: Vec<_> = events.iter().filter(|e|
        matches!(e.event, OspfEvent::HelloIntervalMismatch { .. })
    ).collect();

    if mismatches.is_empty() { return None; }

    let mut evidence = Vec::new();
    let mut routers = std::collections::HashSet::new();
    let mut details = Vec::new();

    for te in &mismatches {
        if let OspfEvent::HelloIntervalMismatch { router_a, router_b, interval_a, interval_b, .. } = &te.event {
            routers.insert(router_a.clone());
            routers.insert(router_b.clone());
            details.push(format!("{} hello={}s vs {} hello={}s", router_a, interval_a, router_b, interval_b));
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "HelloIntervalMismatch".into(),
                description: details.last().unwrap().clone(),
            });
        }
    }

    let routers: Vec<_> = routers.into_iter().collect();

    Some(RootCause {
        kind: RootCauseKind::HelloTimerMismatch,
        severity: RootCauseSeverity::Critical,
        headline: format!("Timer mismatch: {}", details.join("; ")),
        impact: "OSPF adjacency will never form. RFC 2328 requires identical Hello and Dead intervals on both ends of a link. Routers silently discard Hello packets with mismatched timers.".into(),
        remediation: "Set identical `ip ospf hello-interval` and `ip ospf dead-interval` on both interfaces. Default: hello=10s, dead=40s. Verify with `show ip ospf interface`.".into(),
        evidence,
        secondary_effects: vec![
            "Adjacency permanently stuck in Init or 2-Way state".into(),
            "Routes from affected neighbor not installed in RIB".into(),
        ],
        affected_routers: routers,
        first_seen: mismatches[0].ts,
        last_seen: mismatches.last().unwrap().ts,
    })
}

fn detect_duplicate_rid(events: &[TimedEvent]) -> Option<RootCause> {
    let dups: Vec<_> = events.iter().filter(|e|
        matches!(e.event, OspfEvent::DuplicateRouterId { .. })
    ).collect();

    if dups.is_empty() { return None; }

    let mut evidence = Vec::new();
    let mut routers = Vec::new();

    for te in &dups {
        if let OspfEvent::DuplicateRouterId { router_id, ip_a, ip_b, .. } = &te.event {
            routers.push(router_id.clone());
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "DuplicateRouterId".into(),
                description: format!("RID {} claimed by {} AND {}", router_id, ip_a, ip_b),
            });
        }
    }

    Some(RootCause {
        kind: RootCauseKind::DuplicateRouterId,
        severity: RootCauseSeverity::Critical,
        headline: format!("Duplicate Router-ID detected: {}", routers.join(", ")),
        impact: "All routers in the area are receiving conflicting LSAs from the same Router-ID. The LSDB is corrupted — routing decisions based on this data are unreliable. This affects the entire area, not just the two routers involved.".into(),
        remediation: "Identify all routers with `show ip ospf` and assign unique Router-IDs. Typically set via `router-id` command or by controlling loopback IP addresses. Requires OSPF process restart after change.".into(),
        evidence,
        secondary_effects: vec![
            "LSDB inconsistency across entire area".into(),
            "Routing loops possible".into(),
            "Unpredictable forwarding behavior".into(),
        ],
        affected_routers: routers,
        first_seen: dups[0].ts,
        last_seen: dups.last().unwrap().ts,
    })
}

fn detect_auth_mismatch(events: &[TimedEvent]) -> Option<RootCause> {
    let mismatches: Vec<_> = events.iter().filter(|e|
        matches!(e.event, OspfEvent::AuthMismatch { .. })
    ).collect();

    if mismatches.is_empty() { return None; }

    let mut evidence = Vec::new();
    let mut routers = Vec::new();

    for te in &mismatches {
        if let OspfEvent::AuthMismatch { router_id, auth_type, expected_auth_type, src_ip, .. } = &te.event {
            routers.push(router_id.clone());
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "AuthMismatch".into(),
                description: format!(
                    "{} ({}) uses auth type {} — network expects {}",
                    router_id, src_ip,
                    auth_type_name(*auth_type),
                    auth_type_name(*expected_auth_type)
                ),
            });
        }
    }

    Some(RootCause {
        kind: RootCauseKind::AuthenticationMismatch,
        severity: RootCauseSeverity::Critical,
        headline: "Authentication type mismatch — packets silently rejected".into(),
        impact: "OSPF packets are silently dropped. No error is logged on the receiving router — it simply ignores packets with unexpected authentication type. Adjacency cannot form.".into(),
        remediation: "Verify `ip ospf authentication` config on all interfaces in the area. Types must match: none (0), simple password (1), or MD5 (2). Use `show ip ospf interface` to confirm.".into(),
        evidence,
        secondary_effects: vec![
            "Adjacency silently rejected — no log entry on remote router".into(),
            "May appear as one-sided adjacency in `show ip ospf neighbor`".into(),
        ],
        affected_routers: routers,
        first_seen: mismatches[0].ts,
        last_seen: mismatches.last().unwrap().ts,
    })
}

fn detect_neighbor_flapping(events: &[TimedEvent]) -> Option<RootCause> {
    // Flapping = один и тот же router_id появляется и пропадает
    // Детектируем: NeighborDiscovered после NeighborTimeout для того же RID
    let mut rid_timeline: std::collections::HashMap<String, Vec<(&str, f64)>> = std::collections::HashMap::new();

    for te in events {
        match &te.event {
            OspfEvent::NeighborDiscovered { router_id, .. } => {
                rid_timeline.entry(router_id.clone()).or_default().push(("up", te.ts));
            }
            OspfEvent::NeighborTimeout { router_id, .. } => {
                rid_timeline.entry(router_id.clone()).or_default().push(("down", te.ts));
            }
            _ => {}
        }
    }

    let flapping: Vec<_> = rid_timeline.iter()
        .filter(|(_, timeline)| {
            // Считаем Down события — если больше 1, это flap
            timeline.iter().filter(|(state, _)| *state == "down").count() >= 1
            && timeline.iter().filter(|(state, _)| *state == "up").count() >= 2
        })
        .collect();

    if flapping.is_empty() { return None; }

    let mut evidence = Vec::new();
    let mut routers = Vec::new();
    let mut first_ts = f64::MAX;
    let mut last_ts  = 0f64;

    for (rid, timeline) in &flapping {
        routers.push((*rid).clone());
        for (state, ts) in *timeline {
            if *ts < first_ts { first_ts = *ts; }
            if *ts > last_ts  { last_ts  = *ts; }
            evidence.push(EvidenceRef {
                ts: *ts,
                event_type: if *state == "up" { "NeighborDiscovered".into() } else { "NeighborTimeout".into() },
                description: format!("Neighbor {} went {}", rid, state),
            });
        }
    }

    evidence.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap());

    Some(RootCause {
        kind: RootCauseKind::NeighborFlapping,
        severity: RootCauseSeverity::Warning,
        headline: format!("Neighbor flapping detected: {}", routers.join(", ")),
        impact: "Repeated adjacency up/down cycles cause continuous LSA flooding, CPU spikes on all routers in the area, and intermittent routing instability. Convergence never fully completes.".into(),
        remediation: "Check physical link stability (`show interface` error counters). Verify BFD if configured. Check for duplex mismatch or spanning-tree topology changes on the underlying L2 segment.".into(),
        evidence,
        secondary_effects: vec![
            "Continuous LSA flooding from each flap".into(),
            "Increased SPF calculation frequency on all area routers".into(),
            "Intermittent packet loss during reconvergence".into(),
        ],
        affected_routers: routers,
        first_seen: first_ts,
        last_seen: last_ts,
    })
}

fn detect_dr_instability(events: &[TimedEvent]) -> Option<RootCause> {
    let dr_changes: Vec<_> = events.iter().filter(|e|
        matches!(e.event, OspfEvent::DrChange { .. })
    ).collect();

    if dr_changes.is_empty() { return None; }

    let mut evidence = Vec::new();
    let mut areas = std::collections::HashSet::new();

    for te in &dr_changes {
        if let OspfEvent::DrChange { area, old_dr, new_dr, router_id, .. } = &te.event {
            areas.insert(area.clone());
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "DrChange".into(),
                description: format!("Area {} DR changed: {} → {} (reported by {})", area, old_dr, new_dr, router_id),
            });
        }
    }

    let areas: Vec<_> = areas.into_iter().collect();

    Some(RootCause {
        kind: RootCauseKind::DrInstability,
        severity: RootCauseSeverity::Warning,
        headline: format!("{} DR change(s) in area(s) {}", dr_changes.len(), areas.join(", ")),
        impact: "Each DR change triggers a Network-LSA update and partial SPF recalculation on all routers in the segment. Multiple changes indicate a flapping DR candidate or priority misconfiguration.".into(),
        remediation: "Pin DR/BDR with explicit `ip ospf priority` — set priority=0 on routers that should never be DR. Verify the intended DR has highest priority or highest RID as tiebreaker.".into(),
        evidence,
        secondary_effects: vec![
            "Network-LSA churn in affected area".into(),
            "SPF triggered on every DR change".into(),
        ],
        affected_routers: areas,
        first_seen: dr_changes[0].ts,
        last_seen: dr_changes.last().unwrap().ts,
    })
}

fn detect_topology_instability(events: &[TimedEvent]) -> Option<RootCause> {
    let floods: Vec<_> = events.iter().filter(|e|
        matches!(e.event, OspfEvent::LsaFlood { .. })
    ).collect();

    if floods.is_empty() { return None; }

    let mut evidence = Vec::new();
    let mut routers = Vec::new();
    let total_lsu: usize = floods.iter().map(|te| {
        if let OspfEvent::LsaFlood { lsu_count, .. } = &te.event { *lsu_count } else { 0 }
    }).sum();

    for te in &floods {
        if let OspfEvent::LsaFlood { router_id, lsu_count, window_ms, .. } = &te.event {
            routers.push(router_id.clone());
            evidence.push(EvidenceRef {
                ts: te.ts,
                event_type: "LsaFlood".into(),
                description: format!("{} sent {} LSUs in {:.1}s", router_id, lsu_count, window_ms / 1000.0),
            });
        }
    }

    Some(RootCause {
        kind: RootCauseKind::TopologyInstability,
        severity: RootCauseSeverity::Warning,
        headline: format!("LSA flood detected — {} total LSUs from {} router(s)", total_lsu, routers.len()),
        impact: "High LSU rate indicates topology churn — likely a flapping link or unstable neighbor. Every LSU triggers SPF recalculation on all routers in the area, causing CPU spikes and routing table instability.".into(),
        remediation: "Identify the source of instability with `show ip ospf statistics`. Enable OSPF flood reduction if appropriate. Check for interface errors on links connected to flooding routers.".into(),
        evidence,
        secondary_effects: vec![
            "Elevated CPU on all area routers during flood".into(),
            "Routing table churn during reconvergence".into(),
        ],
        affected_routers: routers,
        first_seen: floods[0].ts,
        last_seen: floods.last().unwrap().ts,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn assess_convergence(events: &[TimedEvent]) -> bool {
    // Считаем сеть сконвергированной если:
    // - нет критических событий в последние 20% capture
    // - или явное ConvergenceDetected событие
    if events.iter().any(|e| matches!(e.event, OspfEvent::ConvergenceDetected { .. })) {
        return true;
    }

    if events.is_empty() { return true; }

    let first = events.first().unwrap().ts;
    let last  = events.last().unwrap().ts;
    let window_start = first + (last - first) * 0.8;

    let late_anomalies = events.iter().filter(|e|
        e.ts >= window_start &&
        matches!(e.severity, Severity::Warning | Severity::Critical)
    ).count();

    late_anomalies == 0
}

fn build_verdict(causes: &[RootCause], converged: bool) -> String {
    if causes.is_empty() {
        return "Network operating normally. No anomalies detected.".into();
    }

    let critical: Vec<_> = causes.iter().filter(|c| c.severity == RootCauseSeverity::Critical).collect();
    let warnings: Vec<_> = causes.iter().filter(|c| c.severity == RootCauseSeverity::Warning).collect();

    if !critical.is_empty() {
        let titles: Vec<_> = critical.iter().map(|c| c.kind.title()).collect();
        format!(
            "{} critical issue(s) detected: {}. {}",
            critical.len(),
            titles.join(", "),
            if converged { "Network may have recovered by end of capture." }
            else { "Network had NOT converged by end of capture." }
        )
    } else {
        let titles: Vec<_> = warnings.iter().map(|c| c.kind.title()).collect();
        format!(
            "{} warning(s): {}. {}",
            warnings.len(),
            titles.join(", "),
            if converged { "Network converged." } else { "Instability persisted." }
        )
    }
}

fn build_action_plan(causes: &[RootCause]) -> Vec<String> {
    let mut plan = Vec::new();

    for cause in causes {
        match cause.kind {
            RootCauseKind::DuplicateRouterId => {
                plan.push("1. URGENT: Fix duplicate Router-ID — run `show ip ospf` on all routers, assign unique IDs".into());
            }
            RootCauseKind::MtuMismatch => {
                plan.push("2. Fix MTU mismatch — verify `show interface` on both sides of affected links".into());
            }
            RootCauseKind::HelloTimerMismatch => {
                plan.push("3. Fix timer mismatch — align hello/dead intervals, verify with `show ip ospf interface`".into());
            }
            RootCauseKind::AuthenticationMismatch => {
                plan.push("4. Fix authentication — verify `ip ospf authentication` type matches on both ends".into());
            }
            RootCauseKind::NeighborFlapping => {
                plan.push("5. Investigate flapping neighbor — check L1/L2 stability, error counters, BFD config".into());
            }
            RootCauseKind::DrInstability => {
                plan.push("6. Stabilize DR — set explicit `ip ospf priority` on intended DR/BDR".into());
            }
            RootCauseKind::TopologyInstability => {
                plan.push("7. Find LSA flood source — `show ip ospf statistics`, check interface error counters".into());
            }
            RootCauseKind::Clean => {}
        }
    }

    if plan.is_empty() {
        plan.push("No action required.".into());
    }

    plan
}

fn auth_type_name(t: u16) -> &'static str {
    match t {
        0 => "None",
        1 => "Simple Password",
        2 => "MD5",
        _ => "Unknown",
    }
}
