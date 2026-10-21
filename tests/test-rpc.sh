#!/usr/bin/env bash
# test-rpc.sh — Integration tests for openmediavault-cterm RPC methods.
#
# Usage: sudo ./tests/test-rpc.sh
#
# Exercises the plugin RPC methods against the live OMV configuration
# database, then deploys a few reverse proxy configurations and checks the
# generated backend config, nginx location and listening address. The
# original cterm configuration is restored and redeployed on exit.
#
# Requirements:
#   - Run as root
#   - OMV with the cterm plugin installed
#
# Optional environment:
#   OMVTEST_NO_DEPLOY=1    skip the deploy tests (they restart omv_cterm and
#                          reload nginx)
#   OMVTEST_NETWORK=1      also run updateComponents (downloads the
#                          front-end components from the internet)

set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Colours / counters
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
declare -a FAILED_TESTS=()

section() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}" >&2; }
info()    { echo -e "  ${YELLOW}»${NC} $*" >&2; }

_pass() { echo -e "  ${GREEN}PASS${NC}  $1" >&2; ((PASS++)) || true; }
_fail() {
    echo -e "  ${RED}FAIL${NC}  $1" >&2
    [ -n "${2:-}" ] && echo -e "         ${RED}→${NC} $2" >&2
    ((FAIL++)) || true
    FAILED_TESTS+=("$1")
}
_skip() { echo -e "  ${YELLOW}SKIP${NC}  $1${2:+  ($2)}" >&2; ((SKIP++)) || true; }

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

# Last successful RPC output is stored here.  Never call assert_rpc inside
# a $() subshell — that would prevent PASS/FAIL counter updates from
# propagating back to the parent shell.
RPC_OUT=""

# Assert RPC succeeds. Optional 5th arg: grep pattern that must appear.
# Result JSON is available in $RPC_OUT after the call.
assert_rpc() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local out ec=0
    RPC_OUT=""
    out=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        _fail "$desc" "$(echo "$out" | tail -3)"
        return 1
    fi
    if [ -n "$pattern" ] && ! echo "$out" | grep -q "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in: ${out:0:300}"
        return 1
    fi
    _pass "$desc"
    RPC_OUT="$out"
    return 0
}

# Assert RPC fails (non-zero exit or output contains Exception).
# Optional 5th arg: case-insensitive grep pattern that must appear in the
# error output. Optional 6th arg: user to call the RPC as (default: admin).
assert_rpc_fails() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-} user=${6:-admin}
    local out ec=0
    out=$(omv-rpc -u "$user" "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -eq 0 ] && ! echo "$out" | grep -qi "exception"; then
        _fail "$desc" "Expected failure but RPC succeeded"
        return 1
    fi
    if [ -n "$pattern" ] && ! echo "$out" | grep -qi -- "$pattern"; then
        _fail "$desc" "Failed, but '$pattern' not found in: ${out:0:300}"
        return 1
    fi
    _pass "$desc"
    return 0
}

# Call a background RPC, wait for the task and assert it finished without
# an exception. Optional 5th arg: grep pattern that must appear in the output.
assert_rpc_bg() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local filename ec=0
    filename=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        _fail "$desc" "Failed to start bg task: ${filename:0:200}"
        return 1
    fi
    filename=$(echo "$filename" | tr -d '"')
    local timeout=300 elapsed=0 poll_ec=0 poll_out
    while [ $elapsed -lt $timeout ]; do
        poll_out=$(omv-rpc -u admin "Exec" "getOutput" \
            "{\"filename\":\"$filename\",\"pos\":0}" 2>&1)
        poll_ec=$?
        [ $poll_ec -ne 0 ] && break
        echo "$poll_out" | grep -q '"running":true\|"running": true' || break
        sleep 2; ((elapsed += 2)) || true
    done
    if [ $elapsed -ge $timeout ]; then
        _fail "$desc" "Bg task timed out after ${timeout}s"
        return 1
    fi
    if [ $poll_ec -ne 0 ] || echo "$poll_out" | grep -q "Exception"; then
        _fail "$desc" "${poll_out:0:300}"
        return 1
    fi
    if [ -n "$pattern" ] && ! echo "$poll_out" | grep -q "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in output"
        return 1
    fi
    _pass "$desc"
    return 0
}

# Extract a JSON field value.
json_get() { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$2',''))" 2>/dev/null; }

# Assert two values are equal.
assert_eq() {
    local desc=$1 expected=$2 actual=$3
    if [ "$expected" = "$actual" ]; then
        _pass "$desc"
    else
        _fail "$desc" "expected '$expected', got '$actual'"
    fi
}

# Assert on-disk file $2 contains a line matching the regex $3.
assert_file_matches() {
    local desc=$1 file=$2 regex=$3
    if [ ! -f "$file" ]; then
        _fail "$desc" "$file does not exist"
    elif grep -qE -- "$regex" "$file"; then
        _pass "$desc"
    else
        _fail "$desc" "no line matching '$regex' in $file"
    fi
}

# ---------------------------------------------------------------------------
# Saved state — restored on exit
# ---------------------------------------------------------------------------
CONF_ID="conf.service.cterm"
CTERM_CONF="/etc/omv_cterm.conf"
NGINX_CONF="/etc/nginx/openmediavault-webgui.d/openmediavault-cterm.conf"
FORM_YAML="/usr/share/openmediavault/workbench/component.d/omv-services-cterm-form-page.yaml"
# Non-admin username used for the RPC role checks. It does not have to exist:
# omv-rpc builds a user-role context for any name other than admin.
NONADMIN_USER="omvtest_nonadmin"
TEST_BASEPATH="/omvtest_cterm"

ORIG_CONF=$(omv-confdbadm read "$CONF_ID" 2>/dev/null)
if [ -z "$ORIG_CONF" ]; then
    echo "Could not read $CONF_ID. Is openmediavault-cterm installed?" >&2
    exit 1
fi
cleanup() {
    section "Cleanup"
    info "Restoring original cterm config"
    omv-confdbadm update "$CONF_ID" "$ORIG_CONF" >/dev/null 2>&1 || true
    # Cterm.set marks the module dirty; deploying with --append-dirty puts
    # the original config back in place and clears the web UI banner.
    info "Redeploying cterm with the original config"
    omv-salt deploy run --quiet --append-dirty cterm >/dev/null 2>&1 || true
    echo "" >&2
}
trap cleanup EXIT

# Build Cterm.set params from the original config with JSON overrides
# applied, e.g. cterm_params '{"basepath":"x"}'.
cterm_params() {
    local overrides=${1:-'{}'}
    echo "$ORIG_CONF" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = ('enable', 'host', 'port', 'hostshell', 'enablenginx',
        'autosecret', 'autouser', 'basepath')
p = {k: d.get(k) for k in keys}
p['enablenginx'] = bool(p['enablenginx'])
p.update(json.loads('''$overrides'''))
print(json.dumps(p))"
}

# Read a key from the [server] section of the deployed backend config.
conf_value() {
    python3 -c "
import configparser, sys
c = configparser.ConfigParser()
c.read('$CTERM_CONF')
print(c.get('server', '$1', fallback=''))"
}

# Addresses omv_cterm listens on for port $1, one per line. Waits up to 15s
# for the service to come up after a restart.
listen_addrs() {
    local port=$1 out
    for _ in $(seq 1 15); do
        out=$(ss -Hltn "sport = :$port" 2>/dev/null | awk '{print $4}' | sed 's/:[0-9]*$//')
        [ -n "$out" ] && break
        sleep 1
    done
    echo "$out"
}

ORIG_PORT=$(json_get "$ORIG_CONF" "port")
WEBADMIN=$(omv-confdbadm read "conf.webadmin" 2>/dev/null)
WEB_SSL=$(echo "$WEBADMIN" | python3 -c "import sys,json; print('1' if json.load(sys.stdin).get('enablessl') else '0')")

# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------
section "get"

assert_rpc "get" "Cterm" "get" '{}' '"basepath"'
GET_OUT="$RPC_OUT"
for key in enable host port hostshell enablenginx autosecret autouser basepath \
    ssl proxypath omvuser hmac ts; do
    if echo "$GET_OUT" | python3 -c "import sys,json; sys.exit(0 if '$key' in json.load(sys.stdin) else 1)"; then
        _pass "get returns '$key'"
    else
        _fail "get returns '$key'" "missing from: ${GET_OUT:0:300}"
    fi
done

if [ "$WEB_SSL" = "1" ]; then
    assert_eq "get ssl reflects webadmin ssl" "https" "$(json_get "$GET_OUT" ssl)"
else
    assert_eq "get ssl reflects webadmin ssl" "" "$(json_get "$GET_OUT" ssl)"
fi

# The auto-login hmac must verify against the deployed secret.
if [ -r /etc/omv_cterm.secret ]; then
    HMAC_OK=$(echo "$GET_OUT" | python3 -c "
import sys, json, hmac, hashlib
d = json.load(sys.stdin)
secret = open('/etc/omv_cterm.secret').read().strip().encode()
msg = ('%s:%s' % (d['omvuser'], d['ts'])).encode()
print(hmac.compare_digest(hmac.new(secret, msg, hashlib.sha256).hexdigest(), d['hmac']))")
    assert_eq "get hmac verifies against the secret" "True" "$HMAC_OK"
else
    _skip "get hmac verifies against the secret" "/etc/omv_cterm.secret not deployed"
fi

assert_rpc_fails "get rejects non-admin" "Cterm" "get" '{}' "" "$NONADMIN_USER"

# ---------------------------------------------------------------------------
# set — base path normalization
# ---------------------------------------------------------------------------
section "set (base path)"

for pair in "omvtest|/omvtest" "/omvtest/|/omvtest" "//omvtest//|/omvtest" \
    " /omv/test/ |/omv/test" "/|" "|"; do
    input="${pair%%|*}"
    expected="${pair#*|}"
    if assert_rpc "set basepath '$input'" "Cterm" "set" \
        "$(cterm_params "{\"basepath\":\"$input\"}")"; then
        assert_eq "set stores basepath '$input' as '$expected'" "$expected" \
            "$(json_get "$RPC_OUT" basepath)"
        assert_rpc "get after basepath '$input'" "Cterm" "get" '{}'
        assert_eq "get proxypath for basepath '$input'" "$expected" \
            "$(json_get "$RPC_OUT" proxypath)"
    fi
done

# get adds ssl/proxypath/omvuser/hmac/ts; the UI posts them back on save.
SET_WITH_EXTRAS=$(cterm_params '{"ssl":"https","proxypath":"/x","omvuser":"u","hmac":"h","ts":"1"}')
assert_rpc "set ignores fields added by get" "Cterm" "set" "$SET_WITH_EXTRAS"

# ---------------------------------------------------------------------------
# set — auto-login secret
# ---------------------------------------------------------------------------
section "set (auto-login secret)"

secret_len() {
    local out
    out=$(omv-rpc -u admin "Cterm" "set" "$(cterm_params "{\"autosecret\":\"$1\"}")" 2>/dev/null) || return 1
    json_get "$out" autosecret | tr -d '\n' | wc -c
}

len=$(secret_len "random")
if [ -n "$len" ] && [ "$len" -ge 32 ] && [ "$len" -le 64 ]; then
    _pass "set autosecret 'random' generates 32-64 chars"
else
    _fail "set autosecret 'random' generates 32-64 chars" "length '$len'"
fi
assert_eq "set autosecret 'random40' generates 40 chars" "40" "$(secret_len random40)"
assert_eq "set autosecret 'random10' clamps to 32 chars" "32" "$(secret_len random10)"
assert_eq "set autosecret 'random99' clamps to 64 chars" "64" "$(secret_len random99)"
assert_eq "set autosecret 'RANDOM48' is case-insensitive" "48" "$(secret_len RANDOM48)"

assert_rpc "set generated secret is URL-safe" "Cterm" "set" \
    "$(cterm_params '{"autosecret":"random64"}')"
if json_get "$RPC_OUT" autosecret | grep -qE '^[A-Za-z0-9_-]{64}$'; then
    _pass "generated secret uses URL-safe characters"
else
    _fail "generated secret uses URL-safe characters" "$(json_get "$RPC_OUT" autosecret)"
fi

LITERAL_SECRET="omvtest_literal_secret_0123456789abcdef"
assert_rpc "set literal secret" "Cterm" "set" \
    "$(cterm_params "{\"autosecret\":\"$LITERAL_SECRET\"}")"
assert_eq "set keeps a literal secret unchanged" "$LITERAL_SECRET" "$(json_get "$RPC_OUT" autosecret)"

assert_rpc "set empty secret (auto-login disabled)" "Cterm" "set" \
    "$(cterm_params '{"autosecret":""}')"
assert_rpc_fails "set rejects short secret" "Cterm" "set" \
    "$(cterm_params '{"autosecret":"tooshort"}')" "too short"

# ---------------------------------------------------------------------------
# set — validation and access
# ---------------------------------------------------------------------------
section "set (validation)"

assert_rpc_fails "set rejects missing params" "Cterm" "set" '{"enable":false}'
assert_rpc_fails "set rejects port below 1024" "Cterm" "set" "$(cterm_params '{"port":80}')"
assert_rpc_fails "set rejects port above 65535" "Cterm" "set" "$(cterm_params '{"port":70000}')"
assert_rpc_fails "set rejects non-admin" "Cterm" "set" "$(cterm_params)" "" "$NONADMIN_USER"

# ---------------------------------------------------------------------------
# enumerateUsers
# ---------------------------------------------------------------------------
section "enumerateUsers"

if assert_rpc "enumerateUsers" "Cterm" "enumerateUsers" '{}'; then
    FIRST=$(echo "$RPC_OUT" | python3 -c "import sys,json; print(repr(json.load(sys.stdin)[0]['name']))")
    assert_eq "enumerateUsers starts with the empty (no user) entry" "''" "$FIRST"
    # The rest of the list is UserMgmt.enumerateUsers (normal users only).
    CTERM_USERS=$(echo "$RPC_OUT" | python3 -c "import sys,json; print(' '.join(u['name'] for u in json.load(sys.stdin)[1:]))")
    OMV_USERS=$(omv-rpc -u admin "UserMgmt" "enumerateUsers" '{}' 2>/dev/null \
        | python3 -c "import sys,json; print(' '.join(u['name'] for u in json.load(sys.stdin)))")
    assert_eq "enumerateUsers lists the UserMgmt users after the empty entry" "$OMV_USERS" "$CTERM_USERS"
fi
assert_rpc_fails "enumerateUsers rejects non-admin" "Cterm" "enumerateUsers" '{}' "" "$NONADMIN_USER"

# ---------------------------------------------------------------------------
# updateComponents
# ---------------------------------------------------------------------------
section "updateComponents"

assert_rpc_fails "updateComponents rejects non-admin" "Cterm" "updateComponents" '{}' "" "$NONADMIN_USER"
if [ "${OMVTEST_NETWORK:-0}" = "1" ]; then
    assert_rpc_bg "updateComponents" "Cterm" "updateComponents" '{}'
else
    _skip "updateComponents" "set OMVTEST_NETWORK=1 to download components"
fi

# ---------------------------------------------------------------------------
# Workbench — Open UI button
# ---------------------------------------------------------------------------
section "Workbench"

# Regression: behind the reverse proxy the Open UI link was built from the
# page hostname only, dropping a non-default web UI port.
if grep -q "location() | get('origin'), proxypath" "$FORM_YAML"; then
    _pass "Open UI uses the page origin behind the reverse proxy"
else
    _fail "Open UI uses the page origin behind the reverse proxy" "not found in $FORM_YAML"
fi
if grep -q "enablenginx and proxypath" "$FORM_YAML"; then
    _pass "Open UI only uses the proxy link when a base path is set"
else
    _fail "Open UI only uses the proxy link when a base path is set" "not found in $FORM_YAML"
fi

# ---------------------------------------------------------------------------
# Deploy — reverse proxy
# ---------------------------------------------------------------------------
section "Deploy (reverse proxy)"

# Set the config, deploy it, and leave the result on disk for inspection.
deploy_cterm() {
    local desc=$1 overrides=$2
    assert_rpc "set ($desc)" "Cterm" "set" "$(cterm_params "$overrides")" || return 1
    if omv-salt deploy run --quiet cterm >/dev/null 2>&1; then
        _pass "deploy ($desc)"
    else
        _fail "deploy ($desc)" "omv-salt deploy run cterm failed"
        return 1
    fi
}

if [ "${OMVTEST_NO_DEPLOY:-0}" = "1" ]; then
    _skip "deploy tests" "OMVTEST_NO_DEPLOY=1"
else
    SECRET='{"autosecret":"omvtest_deploy_secret_0123456789abcdef"}'
    merge() { python3 -c "import json,sys; a=json.loads(sys.argv[1]); a.update(json.loads(sys.argv[2])); print(json.dumps(a))" "$1" "$2"; }

    # Regression (compose #102): with the reverse proxy on, the backend must
    # speak plain HTTP and listen on loopback only.
    if deploy_cterm "proxy with base path" \
        "$(merge "$SECRET" "{\"enable\":true,\"enablenginx\":true,\"host\":\"0.0.0.0\",\"basepath\":\"$TEST_BASEPATH\"}")"; then
        assert_eq "proxy: backend host is loopback" "127.0.0.1" "$(conf_value host)"
        assert_eq "proxy: backend uses plain HTTP" "False" "$(conf_value use_https)"
        assert_eq "proxy: backend basepath" "$TEST_BASEPATH" "$(conf_value basepath)"
        assert_file_matches "proxy: nginx location installed" "$NGINX_CONF" \
            "^location \\^~ $TEST_BASEPATH/ \\{"
        assert_file_matches "proxy: nginx proxies to loopback" "$NGINX_CONF" \
            "proxy_pass +http://127\\.0\\.0\\.1:$ORIG_PORT$TEST_BASEPATH/;"
        addrs=$(listen_addrs "$ORIG_PORT")
        if [ -z "$addrs" ]; then
            _fail "proxy: backend listens only on loopback" "nothing listening on :$ORIG_PORT"
        elif echo "$addrs" | grep -qv '^127\.0\.0\.1$'; then
            _fail "proxy: backend listens only on loopback" "listening on: $(echo $addrs)"
        else
            _pass "proxy: backend listens only on loopback"
        fi
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            "http://127.0.0.1:$ORIG_PORT$TEST_BASEPATH/" 2>/dev/null)
        if [ -n "$code" ] && [ "$code" != "000" ]; then
            _pass "proxy: backend answers plain HTTP on loopback ($code)"
        else
            _fail "proxy: backend answers plain HTTP on loopback" "no response"
        fi
        # Regression: the auto-login redirect dropped the base path, sending
        # the first click of a fresh session to the web UI root.
        GET_OUT=$(omv-rpc -u admin "Cterm" "get" '{}' 2>/dev/null)
        login_qs="user=$(json_get "$GET_OUT" omvuser)&hmac=$(json_get "$GET_OUT" hmac)&ts=$(json_get "$GET_OUT" ts)"
        resp=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 5 \
            "http://127.0.0.1:$ORIG_PORT$TEST_BASEPATH/?$login_qs" 2>/dev/null)
        case "$resp" in
            "302 http://127.0.0.1:$ORIG_PORT$TEST_BASEPATH/")
                _pass "proxy: auto-login redirect keeps the base path" ;;
            302*)
                _fail "proxy: auto-login redirect keeps the base path" "redirected to: ${resp#302 }" ;;
            *)
                _skip "proxy: auto-login redirect keeps the base path" \
                    "auto-login not accepted for '$(json_get "$GET_OUT" omvuser)' (HTTP ${resp%% *})" ;;
        esac
        if [ "$WEB_SSL" = "1" ]; then
            web_url="https://127.0.0.1:$(json_get "$WEBADMIN" sslport)"
        else
            web_url="http://127.0.0.1:$(json_get "$WEBADMIN" port)"
        fi
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
            "$web_url$TEST_BASEPATH/" 2>/dev/null)
        case "$code" in
            2??|3??|401|403) _pass "proxy: web server proxies $TEST_BASEPATH/ ($code)" ;;
            *) _fail "proxy: web server proxies $TEST_BASEPATH/" "HTTP '$code' from $web_url$TEST_BASEPATH/" ;;
        esac
    fi

    # Reverse proxy ticked without a base path: no nginx location is
    # installed, so the backend must stay directly reachable as configured.
    if deploy_cterm "proxy without base path" \
        "$(merge "$SECRET" '{"enable":true,"enablenginx":true,"host":"0.0.0.0","basepath":""}')"; then
        assert_eq "proxy, no base path: backend host as configured" "0.0.0.0" "$(conf_value host)"
        if [ "$WEB_SSL" = "1" ]; then
            assert_eq "proxy, no base path: backend follows webadmin ssl" "True" "$(conf_value use_https)"
        else
            assert_eq "proxy, no base path: backend follows webadmin ssl" "False" "$(conf_value use_https)"
        fi
        if [ -e "$NGINX_CONF" ]; then
            _fail "proxy, no base path: nginx location removed" "$NGINX_CONF exists"
        else
            _pass "proxy, no base path: nginx location removed"
        fi
        addrs=$(listen_addrs "$ORIG_PORT")
        if echo "$addrs" | grep -qE '^(0\.0\.0\.0|\*|\[::\])$'; then
            _pass "proxy, no base path: backend listens on all interfaces"
        else
            _fail "proxy, no base path: backend listens on all interfaces" "listening on: '$(echo $addrs)'"
        fi
    fi

    # Reverse proxy off: base path is served directly by the backend.
    if deploy_cterm "no proxy" \
        "$(merge "$SECRET" "{\"enable\":true,\"enablenginx\":false,\"host\":\"0.0.0.0\",\"basepath\":\"$TEST_BASEPATH\"}")"; then
        assert_eq "no proxy: backend host as configured" "0.0.0.0" "$(conf_value host)"
        if [ "$WEB_SSL" = "1" ]; then
            assert_eq "no proxy: backend follows webadmin ssl" "True" "$(conf_value use_https)"
        else
            assert_eq "no proxy: backend follows webadmin ssl" "False" "$(conf_value use_https)"
        fi
        if [ -e "$NGINX_CONF" ]; then
            _fail "no proxy: nginx location removed" "$NGINX_CONF exists"
        else
            _pass "no proxy: nginx location removed"
        fi
        assert_eq "no proxy: secret deployed" "omvtest_deploy_secret_0123456789abcdef" \
            "$(cat /etc/omv_cterm.secret 2>/dev/null)"
    fi

    # Disabled: service stopped and nginx location removed.
    if deploy_cterm "disabled" \
        "$(merge "$SECRET" "{\"enable\":false,\"enablenginx\":true,\"basepath\":\"$TEST_BASEPATH\"}")"; then
        if systemctl is-active --quiet omv_cterm; then
            _fail "disabled: omv_cterm stopped" "service still active"
        else
            _pass "disabled: omv_cterm stopped"
        fi
        if [ -e "$NGINX_CONF" ]; then
            _fail "disabled: nginx location removed" "$NGINX_CONF exists"
        else
            _pass "disabled: nginx location removed"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "" >&2
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}" >&2
if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo -e "${RED}Failed tests:${NC}" >&2
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  - $t" >&2
    done
    exit 1
fi
exit 0
