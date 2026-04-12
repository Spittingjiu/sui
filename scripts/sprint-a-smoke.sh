#!/usr/bin/env bash
set -euo pipefail

# Sprint A smoke checks for SUI panel direct login/API
# Usage:
#   PANEL_BASE=http://127.0.0.1:12345 PANEL_USER=admin PANEL_PASS=admin123 bash scripts/sprint-a-smoke.sh

PANEL_BASE="${PANEL_BASE:-http://127.0.0.1:12345}"
PANEL_USER="${PANEL_USER:-admin}"
PANEL_PASS="${PANEL_PASS:-admin123}"
TIMEOUT="${TIMEOUT:-15}"

ok(){ echo "[OK] $*"; }
fail(){ echo "[FAIL] $*"; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOGIN_JSON="$TMP_DIR/login.json"

curl -fsS -m "$TIMEOUT" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"$PANEL_USER\",\"password\":\"$PANEL_PASS\"}" \
  "$PANEL_BASE/auth/login" > "$LOGIN_JSON" || fail "auth/login request failed"

python3 - "$LOGIN_JSON" <<'PY' || fail "auth/login not successful"
import json,sys
p=sys.argv[1]
obj=json.load(open(p,'r',encoding='utf-8'))
if not obj.get('success'):
    raise SystemExit(1)
if not obj.get('token'):
    raise SystemExit(2)
print(obj['token'])
PY
TOKEN="$(python3 - "$LOGIN_JSON" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
print(obj.get('token',''))
PY
)"

[[ -n "$TOKEN" ]] || fail "missing token from auth/login"
ok "direct login"

curl -fsS -m "$TIMEOUT" \
  -H "authorization: Bearer $TOKEN" \
  "$PANEL_BASE/api/panel/token" > "$TMP_DIR/panel-token.json" || fail "api/panel/token failed"
python3 - "$TMP_DIR/panel-token.json" <<'PY' || fail "api/panel/token invalid json"
import json,sys
obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
assert obj.get('success') is True
assert isinstance((obj.get('obj') or {}).get('token',''), str)
PY
ok "panel token api"

curl -fsS -m "$TIMEOUT" \
  -H "authorization: Bearer $TOKEN" \
  "$PANEL_BASE/api/view/bootstrap" > "$TMP_DIR/bootstrap.json" || fail "api/view/bootstrap failed"
python3 - "$TMP_DIR/bootstrap.json" <<'PY' || fail "api/view/bootstrap invalid json"
import json,sys
obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
assert obj.get('success') is True
PY
ok "bootstrap api"

echo "Sprint A SUI smoke passed for $PANEL_BASE"
