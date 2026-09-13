#!/usr/bin/env bash
# Diagnose a deployed llama-server (router mode) without changing anything.
#
# Usage:
#   contrib/gx10-deploy/troubleshoot.sh                    # against localhost
#   BASE=https://llama.example.local:8443 \
#     LLAMA_API_KEY=... contrib/gx10-deploy/troubleshoot.sh
#   contrib/gx10-deploy/troubleshoot.sh --load             # also load idle models
#
# Read-only: it issues GETs plus one deliberately oversized completion per
# model when --load is given. It never restarts the service or edits config.
#
# On the server host it additionally inspects /etc/llama-server and systemd.
# From a workstation those checks are skipped and only the API is probed.

set -uo pipefail

BASE="${BASE:-https://localhost:8443}"
CONFIG_DIR="${CONFIG_DIR:-/etc/llama-server}"
LOAD_IDLE=0
[ "${1:-}" = "--load" ] && LOAD_IDLE=1

FAIL=0
WARN=0
note()  { printf '    %s\n' "$*"; }
bad()   { printf '    FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
warn()  { printf '    WARN: %s\n' "$*"; WARN=$((WARN+1)); }

# Prefer an explicit key, else the installed one if this is the server host.
KEY="${LLAMA_API_KEY:-}"
if [ -z "$KEY" ] && [ -r "$CONFIG_DIR/api.key" ]; then
    KEY="$(cat "$CONFIG_DIR/api.key")"
fi

api() {
    # $1 = path. Prints body, or nothing on transport failure.
    curl -s --max-time "${2:-30}" "$BASE$1" -H "Authorization: Bearer $KEY"
}

echo "==> endpoint $BASE"
if [ -z "$KEY" ]; then
    bad "no API key: set LLAMA_API_KEY, or run on the server where $CONFIG_DIR/api.key is readable"
    exit 1
fi
code="$(curl -s -o /dev/null --max-time 15 -w '%{http_code}' "$BASE/health" -H "Authorization: Bearer $KEY")"
case "$code" in
    200) note "health 200" ;;
    401) bad  "health 401 - the API key is wrong for this server"; exit 1 ;;
    000) bad  "cannot reach $BASE (TLS or network). Try: openssl s_client -connect <host>:<port>"; exit 1 ;;
    *)   bad  "health returned $code"; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# The headline check: configured context vs what a request can actually use.
#
# llama.cpp splits the KV cache across server slots unless the cache is
# unified (src/llama-context.cpp):
#     kv_unified ? n_ctx_seq = n_ctx : n_ctx_seq = n_ctx / n_seq_max
# so with -np/--parallel N and no --kv-unified, every request only gets
# ctx-size/N tokens. Exceeding that is an HTTP 400
# "request (X tokens) exceeds the available context size (Y tokens)",
# where Y is the divided figure, not the ctx-size you configured.
# ---------------------------------------------------------------------------
echo "==> context budget per model"
models_json="$(api /v1/models 60)"
if [ -z "$models_json" ]; then
    bad "could not list models"
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '%s' "$models_json" > "$tmp/models.json"

ids="$(python3 -c "
import json
d=json.load(open('$tmp/models.json'))
print(' '.join(m['id'] for m in d['data']))
")"

printf '    %-38s %10s %10s %6s %s\n' MODEL CONFIGURED EFFECTIVE SLOTS STATE
for m in $ids; do
    cfg="$(python3 -c "
import json
d=json.load(open('$tmp/models.json'))
for x in d['data']:
    if x['id']=='$m':
        a=x.get('status',{}).get('args',[])
        print(a[a.index('--ctx-size')+1] if '--ctx-size' in a else '-')
        break
")"
    state="$(python3 -c "
import json
d=json.load(open('$tmp/models.json'))
for x in d['data']:
    if x['id']=='$m':
        print(x.get('status',{}).get('value','?'))
        break
")"
    # /props?model=NAME goes through ensure_model, which LOADS an idle model as
    # a side effect. Only ask for it when the model is already loaded, or when
    # --load was given explicitly. Probing every model here would evict resident
    # ones (models-max) and can force-kill another model's in-flight load.
    if [ "$state" != "loaded" ] && [ "$LOAD_IDLE" -eq 1 ]; then
        # One token over any plausible slot size forces the 400 that reports
        # n_ctx exactly. This loads the model, which can take minutes.
        python3 -c "
import json
print(json.dumps({'model':'$m','messages':[{'role':'user','content':'token '*70000}],'max_tokens':8}))
" > "$tmp/req.json"
        curl -s --max-time 1800 -o "$tmp/resp.json" \
            "$BASE/v1/chat/completions" -H "Authorization: Bearer $KEY" \
            -H 'Content-Type: application/json' --data-binary "@$tmp/req.json" >/dev/null
        state="$(python3 -c "
import json
try: print('loaded' if json.load(open('$tmp/resp.json')).get('error') else 'loaded')
except Exception: print('load-failed')
")"
    fi

    if [ "$state" = "loaded" ]; then
        api "/props?model=$m" 60 > "$tmp/props.json"
        eff="$(python3 -c "
import json
try:
    d=json.load(open('$tmp/props.json'))
    print(d.get('default_generation_settings',{}).get('n_ctx') or '-')
except Exception: print('-')
")"
        slots="$(python3 -c "
import json
try: print(json.load(open('$tmp/props.json')).get('total_slots') or '-')
except Exception: print('-')
")"
    else
        # Predict without loading: auto (no explicit --parallel) means 4 slots
        # WITH kv_unified, so the full ctx-size is usable. An explicit
        # --parallel N without --kv-unified divides it.
        read -r eff slots <<EOF
$(python3 -c "
import json
d=json.load(open('$tmp/models.json'))
for x in d['data']:
    if x['id']=='$m':
        a=x.get('status',{}).get('args',[])
        ctx=a[a.index('--ctx-size')+1] if '--ctx-size' in a else None
        par=a[a.index('--parallel')+1] if '--parallel' in a else None
        kvu='--kv-unified' in a
        if ctx is None: print('- -')
        elif par and not kvu: print(f'~{int(ctx)//int(par)} {par}')
        else: print(f'~{ctx} auto')
        break
else: print('- -')
")
EOF
    fi
    printf '    %-38s %10s %10s %6s %s\n' "$m" "$cfg" "$eff" "$slots" "$state"

    # "~" marks a predicted value for a model that was not loaded to measure it.
    effn="${eff#\~}"
    if [ "$cfg" != "-" ] && [ "$effn" != "-" ] && [ "$effn" != "0" ]; then
        python3 -c "
import sys
try: cfg, eff = int('$cfg'), int('$effn')
except ValueError: sys.exit(1)
sys.exit(0 if cfg > eff else 1)
" && warn "$m: requests can only use $effn of the $cfg configured (split across $slots slots)"
    fi
done
if [ "$LOAD_IDLE" -eq 0 ]; then
    note "values marked ~ are predicted from spawn args; idle models are NOT loaded"
    note "pass --load to measure them for real (slow, and it evicts resident models)"
fi

# Two names for one set of weights each spawn their own instance and each count
# against models-max, so duplicates quietly halve the router's capacity.
python3 - "$tmp/models.json" <<'PY'
import collections, json, sys
seen = collections.defaultdict(list)
for m in json.load(open(sys.argv[1]))['data']:
    a = m.get('status', {}).get('args', [])
    if '--hf-repo' in a:
        seen[a[a.index('--hf-repo') + 1]].append(m['id'])
for repo, ids in seen.items():
    if len(ids) > 1:
        print(f"    WARN: {repo} is reachable as {' and '.join(ids)}; "
              f"each loads separately and each counts against models-max")
PY

# ---------------------------------------------------------------------------
# Server-host-only checks.
# ---------------------------------------------------------------------------
if [ -d "$CONFIG_DIR" ]; then
    echo "==> $CONFIG_DIR"

    if [ -r "$CONFIG_DIR/config.yaml" ]; then
        # These five make a spawned child think it is also a router, which
        # then spawns its own children, recursively. See README.md.
        for k in port models-preset models-max models-autoload api-key; do
            if grep -qE "^[[:space:]]*$k[[:space:]]*:" "$CONFIG_DIR/config.yaml"; then
                bad "config.yaml sets '$k' - router-identity keys must live on the unit's ExecStart, not in a file every child re-parses"
            fi
        done
        if p="$(grep -oE "^[[:space:]]*(parallel|np)[[:space:]]*:[[:space:]]*-?[0-9]+" "$CONFIG_DIR/config.yaml")"; then
            note "config.yaml sets:${p#*:} parallel slots"
            grep -qE "^[[:space:]]*kv[-_]unified[[:space:]]*:[[:space:]]*true" "$CONFIG_DIR/config.yaml" \
                || warn "explicit parallel without kv-unified: each request gets ctx-size/parallel tokens"
        fi
    else
        note "config.yaml not readable from here"
    fi

    # The context trap. Leaving parallel unset means auto, and auto is
    # n_parallel=4 WITH kv_unified=true (tools/server/server.cpp), so every
    # request can use the whole ctx-size. Setting parallel explicitly does not
    # turn kv_unified on with it (it defaults false in common/common.h), so
    # n_ctx_seq becomes ctx-size/parallel. Adding "parallel = 2" to a section
    # therefore HALVES its usable context as a side effect, which surfaces much
    # later as a 400 "exceeds the available context size" at half the number
    # the section configures.
    if [ -r "$CONFIG_DIR/models.ini" ]; then
        echo "==> models.ini parallel/kv-unified"
        python3 - "$CONFIG_DIR/models.ini" <<'PY'
import re, sys
sec, cur = {}, None
for line in open(sys.argv[1]):
    line = line.split('#', 1)[0].strip()
    m = re.match(r'^\[(.+)\]$', line)
    if m:
        cur = m.group(1); sec[cur] = {}; continue
    if cur and '=' in line:
        k, v = line.split('=', 1)
        sec[cur][k.strip()] = v.strip()
bad = 0
for name, kv in sec.items():
    par = kv.get('parallel') or kv.get('np')
    if par is None:
        continue
    kvu = (kv.get('kv-unified') or kv.get('kv_unified') or '').lower()
    if par.lstrip('-').isdigit() and int(par) > 0 and kvu not in ('true', '1', 'yes'):
        ctx = kv.get('ctx-size', '?')
        try:
            eff = str(int(ctx) // int(par))
        except ValueError:
            eff = '?'
        print(f"    WARN: [{name}] parallel = {par} without kv-unified: "
              f"ctx-size {ctx} gives only {eff} tokens per request")
        bad += 1
if not bad:
    print("    no section sets parallel without kv-unified")
PY
    fi

    if [ -r "$CONFIG_DIR/api.key" ]; then
        perm="$(stat -c '%a %U:%G' "$CONFIG_DIR/api.key")"
        note "api.key $perm"
        case "$perm" in 640*|600*) ;; *) warn "api.key should be 640 or stricter" ;; esac
    fi

    # A misspelled or gated hf-repo answers 401, never 404, so it looks like a
    # credentials problem. Check existence directly. See README.md.
    if [ -r "$CONFIG_DIR/models.ini" ]; then
        echo "==> hf-repo reachability (models.ini)"
        grep -oE '^[[:space:]]*hf-repo[[:space:]]*=[[:space:]]*[^[:space:]]+' "$CONFIG_DIR/models.ini" \
        | sed 's/.*=[[:space:]]*//' | while read -r repo; do
            base="${repo%%:*}"
            rc="$(curl -s -o /dev/null --max-time 20 -w '%{http_code}' "https://huggingface.co/api/models/$base")"
            if [ "$rc" = "200" ]; then
                printf '    %-58s ok\n' "$base"
            else
                printf '    %-58s HTTP %s (nonexistent, misspelled or gated)\n' "$base" "$rc"
            fi
        done
    fi

    if command -v systemctl >/dev/null 2>&1; then
        echo "==> systemd"
        note "$(systemctl is-active llama-server 2>&1) / $(systemctl is-enabled llama-server 2>&1)"
        # /etc/environment is read into every service on Ubuntu, and every
        # llama-server flag also has an LLAMA_ARG_* env binding, so a stray
        # value here silently overrides the unit.
        if env_leak="$(systemctl show llama-server -p Environment --value 2>/dev/null | tr ' ' '\n' | grep '^LLAMA_ARG_')"; then
            warn "LLAMA_ARG_* in the service environment overrides the unit: $env_leak"
        fi
    fi
fi

echo
if [ "$FAIL" -gt 0 ]; then
    echo "$FAIL failure(s), $WARN warning(s)"
    exit 1
fi
echo "no failures, $WARN warning(s)"
