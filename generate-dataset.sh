#!/usr/bin/env bash
# generate-dataset.sh
# Генерирует OSPF датасет с аномалиями используя FRR + Linux network namespaces
# Требования: Ubuntu/WSL, frr, tcpdump
# Запуск: sudo bash generate-dataset.sh

set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}══════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}══════════════════════════════════════${NC}"; }

# ── Проверки ───────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Запускай от root: sudo bash $0"

for cmd in ip tcpdump ospfd vtysh; do
    command -v "$cmd" &>/dev/null || fail "Не найден: $cmd. Установи FRR: apt install frr"
done

DATASET_DIR="$(dirname "$0")/dataset"
mkdir -p "$DATASET_DIR"

# ── Cleanup helper ─────────────────────────────────────────────────────────
cleanup() {
    info "Чистим namespace и процессы..."
    for ns in r1 r2; do
        ip netns del "$ns" 2>/dev/null || true
    done
    pkill -f "ospfd --config" 2>/dev/null || true
    pkill -f "tcpdump.*veth"  2>/dev/null || true
    rm -f /tmp/ospf-*.conf /tmp/ospf-*.pid /tmp/ospf-*.log
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════

# Создаём пару namespace + veth
setup_namespaces() {
    local ns1=$1 ns2=$2 ip1=$3 ip2=$4 mtu1=${5:-1500} mtu2=${6:-1500}

    info "Поднимаем namespace: $ns1 ($ip1) <-> $ns2 ($ip2) | MTU $mtu1/$mtu2"

    ip netns add "$ns1"
    ip netns add "$ns2"

    ip link add "veth-${ns1}" type veth peer name "veth-${ns2}"
    ip link set "veth-${ns1}" netns "$ns1"
    ip link set "veth-${ns2}" netns "$ns2"

    ip netns exec "$ns1" ip link set lo up
    ip netns exec "$ns2" ip link set lo up

    ip netns exec "$ns1" ip link set "veth-${ns1}" mtu "$mtu1" up
    ip netns exec "$ns2" ip link set "veth-${ns2}" mtu "$mtu2" up

    ip netns exec "$ns1" ip addr add "${ip1}/24" dev "veth-${ns1}"
    ip netns exec "$ns2" ip addr add "${ip2}/24" dev "veth-${ns2}"
}

# Пишем конфиг FRR ospfd
write_ospf_conf() {
    local ns=$1 router_id=$2 network=$3 area=${4:-0.0.0.0}
    local hello=${5:-10} dead=${6:-40} auth_type=${7:-none} auth_key=${8:-""}
    local conf="/tmp/ospf-${ns}.conf"

    cat > "$conf" <<EOF
hostname ospfd-${ns}
log file /tmp/ospf-${ns}.log

interface veth-${ns}
  ip ospf hello-interval ${hello}
  ip ospf dead-interval ${dead}
EOF

    if [[ "$auth_type" == "md5" ]]; then
        echo "  ip ospf authentication message-digest" >> "$conf"
        echo "  ip ospf message-digest-key 1 md5 ${auth_key}" >> "$conf"
    elif [[ "$auth_type" == "simple" ]]; then
        echo "  ip ospf authentication" >> "$conf"
        echo "  ip ospf authentication-key ${auth_key}" >> "$conf"
    fi

    cat >> "$conf" <<EOF
!
router ospf
  ospf router-id ${router_id}
  network ${network} area ${area}
EOF

    if [[ "$auth_type" == "md5" ]]; then
        echo "  area ${area} authentication message-digest" >> "$conf"
    elif [[ "$auth_type" == "simple" ]]; then
        echo "  area ${area} authentication" >> "$conf"
    fi

    echo "!" >> "$conf"
    echo "$conf"
}

# Запускаем ospfd в namespace
start_ospfd() {
    local ns=$1 conf=$2
    ip netns exec "$ns" /usr/lib/frr/ospfd \
        --config_file "$conf" \
        --pid_file "/tmp/ospf-${ns}.pid" \
        --socket "/tmp/ospf-${ns}.sock" \
        --vty_port 0 \
        --log_mode file \
        --daemon 2>/dev/null
    sleep 1
}

# Пишем дамп в namespace
capture() {
    local ns=$1 iface=$2 outfile=$3 duration=$4
    info "Capture: $outfile (${duration}s)"
    ip netns exec "$ns" tcpdump -i "$iface" -w "$outfile" proto ospf &
    local PID=$!
    sleep "$duration"
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    ok "Сохранён: $outfile ($(du -h "$outfile" | cut -f1))"
}

# Удаляем namespace и процессы после сценария
teardown() {
    for ns in r1 r2; do
        pkill -f "ospfd.*${ns}" 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    sleep 1
}

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 0: Чистая сходимость (baseline)
# ══════════════════════════════════════════════════════════════════════════
scenario_clean() {
    section "Сценарий 1/6: Clean adjacency (baseline)"
    local dir="$DATASET_DIR/01-clean-adjacency"
    mkdir -p "$dir"

    setup_namespaces r1 r2 10.0.0.1 10.0.0.2

    local c1; c1=$(write_ospf_conf r1 1.1.1.1 "10.0.0.0/24")
    local c2; c2=$(write_ospf_conf r2 2.2.2.2 "10.0.0.0/24")

    start_ospfd r1 "$c1"
    start_ospfd r2 "$c2"

    capture r1 veth-r1 "$dir/capture.pcap" 90

    cat > "$dir/README.md" <<'EOF'
# Clean OSPF Adjacency (Baseline)

## Setup
- R1: router-id 1.1.1.1, 10.0.0.1/24, hello=10s, dead=40s
- R2: router-id 2.2.2.2, 10.0.0.2/24, hello=10s, dead=40s
- No authentication, MTU 1500 on both sides

## Expected analysis result
- 0 anomalies
- NeighborDiscovered × 1
- DrElection × 1
- AdjacencyFormed × 1
- Network converged: YES

## What to observe
Normal adjacency formation sequence:
Hello → 2-Way → ExStart → Exchange (DBD) → Loading (LSR/LSU) → Full
EOF

    teardown
    ok "Сценарий 1 готов"
}

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 2: MTU mismatch
# ══════════════════════════════════════════════════════════════════════════
scenario_mtu_mismatch() {
    section "Сценарий 2/6: MTU Mismatch"
    local dir="$DATASET_DIR/02-mtu-mismatch"
    mkdir -p "$dir"

    # r1 MTU=1500, r2 MTU=1400 — DBD будет показывать разные значения
    setup_namespaces r1 r2 10.0.1.1 10.0.1.2 1500 1400

    local c1; c1=$(write_ospf_conf r1 1.1.1.1 "10.0.1.0/24")
    local c2; c2=$(write_ospf_conf r2 2.2.2.2 "10.0.1.0/24")

    start_ospfd r1 "$c1"
    start_ospfd r2 "$c2"

    # Нужно время чтобы увидеть зависание в ExStart
    capture r1 veth-r1 "$dir/capture.pcap" 120

    cat > "$dir/README.md" <<'EOF'
# MTU Mismatch

## Setup
- R1: router-id 1.1.1.1, 10.0.1.1/24, MTU=1500
- R2: router-id 2.2.2.2, 10.0.1.2/24, MTU=1400

## Expected analysis result
- MtuMismatch: CRITICAL
  - router_id: 2.2.2.2
  - mtu: 1400, expected_mtu: 1500
- Primary cause: MTU Mismatch
- Impact: DBD exchange stalls in ExStart/Exchange
- Network converged: NO

## What to observe
- Hellos exchanged normally (Hello packets don't carry MTU)
- DBD packets show different Interface MTU field
- Routers loop in ExStart — retransmit DBD indefinitely
- Adjacency never reaches Full state

## Key packet: DBD
Filter in Wireshark: `ospf.v2.options.mtu != 0`
Look at "Interface MTU" field in Database Description packets.
EOF

    teardown
    ok "Сценарий 2 готов"
}

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 3: Hello interval mismatch
# ══════════════════════════════════════════════════════════════════════════
scenario_hello_mismatch() {
    section "Сценарий 3/6: Hello Interval Mismatch"
    local dir="$DATASET_DIR/03-hello-mismatch"
    mkdir -p "$dir"

    setup_namespaces r1 r2 10.0.2.1 10.0.2.2

    # R1: hello=10, R2: hello=30 — adjacency не сформируется никогда
    local c1; c1=$(write_ospf_conf r1 1.1.1.1 "10.0.2.0/24" "0.0.0.0" 10 40)
    local c2; c2=$(write_ospf_conf r2 2.2.2.2 "10.0.2.0/24" "0.0.0.0" 30 120)

    start_ospfd r1 "$c1"
    start_ospfd r2 "$c2"

    # 150s чтобы поймать несколько циклов dead interval
    capture r1 veth-r1 "$dir/capture.pcap" 150

    cat > "$dir/README.md" <<'EOF'
# Hello Interval Mismatch

## Setup
- R1: router-id 1.1.1.1, hello=10s, dead=40s
- R2: router-id 2.2.2.2, hello=30s, dead=120s

## Expected analysis result
- HelloIntervalMismatch: CRITICAL
  - router_a: 1.1.1.1, interval_a: 10
  - router_b: 2.2.2.2, interval_b: 30
- Primary cause: Hello/Dead Timer Mismatch
- Impact: Adjacency permanently stuck in Init/2-Way
- Network converged: NO

## What to observe
- Both routers send Hellos at their own interval
- RFC 2328: Hello interval in received packet must match configured value
- Routers silently discard each other's Hellos → stuck in Init
- No DBD packets ever exchanged

## Key field
In Hello packet: "Hello Interval" field must match on both sides.
EOF

    teardown
    ok "Сценарий 3 готов"
}

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 4: Authentication mismatch
# ══════════════════════════════════════════════════════════════════════════
scenario_auth_mismatch() {
    section "Сценарий 4/6: Authentication Mismatch"
    local dir="$DATASET_DIR/04-auth-mismatch"
    mkdir -p "$dir"

    setup_namespaces r1 r2 10.0.3.1 10.0.3.2

    # R1: MD5 auth, R2: no auth
    local c1; c1=$(write_ospf_conf r1 1.1.1.1 "10.0.3.0/24" "0.0.0.0" 10 40 "md5" "secretkey123")
    local c2; c2=$(write_ospf_conf r2 2.2.2.2 "10.0.3.0/24" "0.0.0.0" 10 40 "none")

    start_ospfd r1 "$c1"
    start_ospfd r2 "$c2"

    capture r1 veth-r1 "$dir/capture.pcap" 90

    cat > "$dir/README.md" <<'EOF'
# Authentication Mismatch

## Setup
- R1: router-id 1.1.1.1, MD5 authentication, key="secretkey123"
- R2: router-id 2.2.2.2, no authentication

## Expected analysis result
- AuthMismatch: CRITICAL
  - router_id: 1.1.1.1
  - auth_type: 2 (MD5), expected: 0 (None)
- Primary cause: Authentication Mismatch
- Impact: Packets silently dropped, no error logged on remote
- Network converged: NO

## What to observe
- R1 sends Hellos with auth_type=2 (MD5) + 16-byte auth data
- R2 sends Hellos with auth_type=0 (None)
- Each router ignores the other's packets
- Silent failure — no OSPF error messages

## Key field
In OSPF common header: "Auth Type" field (offset 14-15).
Values: 0=None, 1=Simple, 2=MD5
EOF

    teardown
    ok "Сценарий 4 готов"
}

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 5: Duplicate Router-ID
# ══════════════════════════════════════════════════════════════════════════
scenario_duplicate_rid() {
    section "Сценарий 5/6: Duplicate Router-ID"
    local dir="$DATASET_DIR/05-duplicate-router-id"
    mkdir -p "$dir"

    setup_namespaces r1 r2 10.0.4.1 10.0.4.2

    # Оба роутера с одинаковым router-id 1.1.1.1
    local c1; c1=$(write_ospf_conf r1 1.1.1.1 "10.0.4.0/24")
    local c2; c2=$(write_ospf_conf r2 1.1.1.1 "10.0.4.0/24")  # намеренный дубль

    start_ospfd r1 "$c1"
    start_ospfd r2 "$c2"

    capture r1 veth-r1 "$dir/capture.pcap" 90

    cat > "$dir/README.md" <<'EOF'
# Duplicate Router-ID

## Setup
- R1: router-id 1.1.1.1, 10.0.4.1/24
- R2: router-id 1.1.1.1, 10.0.4.2/24  ← SAME RID

## Expected analysis result
- DuplicateRouterId: CRITICAL
  - router_id: 1.1.1.1
  - ip_a: 10.0.4.1, ip_b: 10.0.4.2
- Primary cause: Duplicate Router-ID
- Impact: LSDB corruption in entire area
- Network converged: NO (or unstable)

## What to observe
- Both routers advertise identical Router-ID in OSPF header
- Conflicting Router-LSAs flood the area
- Each router constantly overwrites the other's LSA
- Routing table becomes inconsistent

## This is detectable because:
Same Router-ID seen from two different source IPs in Hello packets.
EOF

    teardown
    ok "Сценарий 5 готов"
}

# ══════════════════════════════════════════════════════════════════════════
# Сценарий 6: Neighbor flapping (симулируем через kill/restart ospfd)
# ══════════════════════════════════════════════════════════════════════════
scenario_flapping() {
    section "Сценарий 6/6: Neighbor Flapping"
    local dir="$DATASET_DIR/06-neighbor-flapping"
    mkdir -p "$dir"

    setup_namespaces r1 r2 10.0.5.1 10.0.5.2

    local c1; c1=$(write_ospf_conf r1 1.1.1.1 "10.0.5.0/24")
    local c2; c2=$(write_ospf_conf r2 2.2.2.2 "10.0.5.0/24")

    start_ospfd r1 "$c1"
    start_ospfd r2 "$c2"

    # Начинаем запись
    info "Capture: $dir/capture.pcap (180s, с 3 flap циклами)"
    ip netns exec r1 tcpdump -i veth-r1 -w "$dir/capture.pcap" proto ospf &
    TCPDUMP_PID=$!

    # Ждём первой сходимости
    sleep 50
    ok "Adjacency сформирована, начинаем flapping..."

    # Flap 1: убиваем r2 ospfd → ждём dead interval → поднимаем
    info "Flap 1: убиваем ospfd на r2"
    pkill -f "ospfd.*r2" 2>/dev/null || true
    sleep 50   # dead interval = 40s + запас
    info "Flap 1: поднимаем ospfd на r2"
    start_ospfd r2 "$c2"
    sleep 30

    # Flap 2
    info "Flap 2"
    pkill -f "ospfd.*r2" 2>/dev/null || true
    sleep 50
    start_ospfd r2 "$c2"
    sleep 10   # не даём полностью сойтись

    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true

    ok "Сохранён: $dir/capture.pcap ($(du -h "$dir/capture.pcap" | cut -f1))"

    cat > "$dir/README.md" <<'EOF'
# Neighbor Flapping

## Setup
- R1: router-id 1.1.1.1 (стабильный)
- R2: router-id 2.2.2.2 (намеренно перезапускается 2 раза)

## Timeline
- t=0s:   adjacency forming
- t=50s:  R2 goes DOWN (ospfd killed)
- t=100s: R2 comes UP again (ospfd restarted)
- t=130s: R2 goes DOWN again
- t=180s: capture ends

## Expected analysis result
- NeighborFlapping: WARNING
  - router_id: 2.2.2.2
  - up/down cycles: 2+
- Secondary effects: LSA flood, SPF churn
- Network converged: NO

## What to observe
- NeighborDiscovered followed by NeighborTimeout, repeat
- LSU burst after each flap (topology update flood)
- Hello gaps during down periods
EOF

    teardown
    ok "Сценарий 6 готов"
}

# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════
main() {
    section "OSPF Dataset Generator"
    info "Output: $DATASET_DIR"
    echo ""

    # Проверяем что FRR ospfd доступен
    if ! command -v /usr/lib/frr/ospfd &>/dev/null; then
        # Пробуем альтернативный путь
        if command -v ospfd &>/dev/null; then
            # Патчим путь
            sed -i 's|/usr/lib/frr/ospfd|ospfd|g' "$0"
        else
            fail "ospfd не найден. Установи: apt install frr && sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons"
        fi
    fi

    scenario_clean
    scenario_mtu_mismatch
    scenario_hello_mismatch
    scenario_auth_mismatch
    scenario_duplicate_rid
    scenario_flapping

    section "Готово"
    echo ""
    info "Датасет:"
    find "$DATASET_DIR" -name "*.pcap" | while read f; do
        echo -e "  ${GREEN}$(basename $(dirname $f))${NC} → $f ($(du -h "$f" | cut -f1))"
    done
    echo ""
    info "Проверяй тулзой: перетащи каждый .pcap в браузер и сверяй с README.md"
}

main "$@"
