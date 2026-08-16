#!/bin/bash
# Provision a Scaleway Apple Silicon Mac mini and (optionally) register it as
# a GitHub Actions self-hosted runner for this repo, so the vz boot smoke can
# run on bare metal (GitHub-hosted macOS runners are VMs without nested
# virtualization — VZVirtualMachine.isSupported is false there).
#
# !!! COST: Scaleway Apple Silicon has a 24-HOUR MINIMUM allocation
# !!! (licensing requirement). An M4 at ~EUR 0.22/h means ~EUR 5.30 minimum
# !!! even if you delete it after ten minutes. Delete when done:
# !!!   ./scripts/provision-scaleway-runner.sh delete <server-id>
#
# Usage:
#   SCW_SECRET_KEY=...  SCW_PROJECT_ID=...  ./scripts/provision-scaleway-runner.sh
#   ./scripts/provision-scaleway-runner.sh delete <server-id>
#
# Env:
#   SCW_SECRET_KEY   (required) Scaleway API secret key
#   SCW_PROJECT_ID   (required for create) Scaleway project ID
#   SCW_ZONE         zone (default fr-par-1 — where M4s live)
#   SCW_SERVER_TYPE  server type slug (default: auto-pick the first M4 type)
#   GH_PAT           optional GitHub PAT (repo admin) — if set and the server
#                    becomes SSH-reachable, the runner is registered
#                    automatically via scripts/setup-macos-runner.sh
#   GH_REPO          owner/repo to register the runner for
#                    (default adamwynne/mxc-vz)
set -euo pipefail

API="https://api.scaleway.com/apple-silicon/v1alpha1"
SCW_ZONE="${SCW_ZONE:-fr-par-1}"
# Zones swept for capacity on create (override with SCW_ZONES).
SCW_ZONES="${SCW_ZONES:-fr-par-1 fr-par-3}"
GH_REPO="${GH_REPO:-adamwynne/mxc-vz}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

: "${SCW_SECRET_KEY:?set SCW_SECRET_KEY to your Scaleway API secret key}"

# Calls the API and prints the response body; on a non-2xx status it prints
# the body (Scaleway's error JSON says WHY — permissions, quota, stock) to
# stderr and fails.
api() {
    local method="$1" path="$2" body="${3:-}" out status
    out="$(mktemp)"
    if [[ -n "$body" ]]; then
        status="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" \
            -H "X-Auth-Token: $SCW_SECRET_KEY" \
            -H "Content-Type: application/json" -d "$body" "$API$path")"
    else
        status="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" \
            -H "X-Auth-Token: $SCW_SECRET_KEY" "$API$path")"
    fi
    if [[ "$status" != 2* ]]; then
        echo "error: $method $API$path returned HTTP $status:" >&2
        cat "$out" >&2
        echo >&2
        cat "$out" >> "${ERROR_LOG:-/dev/null}" 2>/dev/null || true
        rm -f "$out"
        return 22
    fi
    cat "$out"
    rm -f "$out"
}

ERROR_LOG="$(mktemp)"

json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

if [[ "${1:-}" == "delete" ]]; then
    server_id="${2:?usage: $0 delete <server-id>}"
    echo "deleting server $server_id (fails if the 24h minimum has not elapsed)"
    api DELETE "/zones/$SCW_ZONE/servers/$server_id"
    echo "delete requested."
    exit 0
fi

: "${SCW_PROJECT_ID:?set SCW_PROJECT_ID to your Scaleway project ID}"

echo
echo ">>> This allocation is billed for a MINIMUM OF 24 HOURS. Ctrl-C now to abort. <<<"
sleep 5

# Idempotency: never create a second Mac if one already exists in any zone.
for zone in $SCW_ZONES; do
    existing="$(api GET "/zones/$zone/servers" | json '
next((s["id"]+" "+s.get("status","") for s in d.get("servers",[]) if s["name"]=="mxc-vz-runner"), "")')"
    if [[ -n "$existing" ]]; then
        echo "a mxc-vz-runner server already exists in $zone: $existing"
        echo "not creating another; delete it first if you want a fresh one."
        exit 0
    fi
done

# Sweep zones x server types: any bare-metal Apple Silicon type runs the boot
# smoke, so on quota (403) or stock (503) failures fall through to the next.
created=""
for zone in $SCW_ZONES; do
    if [[ -n "${SCW_SERVER_TYPE:-}" ]]; then
        candidates="$SCW_SERVER_TYPE"
    else
        types_json="$(api GET "/zones/$zone/server-types")" || continue
        candidates="$(echo "$types_json" | json '
chr(10).join(sorted(
    (t["name"] for t in d["server_types"] if "asahi" not in t["name"].lower()),
    key=lambda n: ("m4-s" not in n.lower(), "m2" not in n.lower(), "m1" not in n.lower(), n)
))')"
    fi
    echo "zone $zone — server type preference order:"
    echo "$candidates"
    while IFS= read -r type; do
        [[ -n "$type" ]] || continue
        echo "trying $type in $zone"
        if created="$(api POST "/zones/$zone/servers" "{
            \"name\": \"mxc-vz-runner\",
            \"project_id\": \"$SCW_PROJECT_ID\",
            \"type\": \"$type\"
        }")"; then
            SCW_SERVER_TYPE="$type"
            SCW_ZONE="$zone"
            break 2
        fi
        echo "  -> creation failed for $type in $zone (see error above); trying next"
    done <<< "$candidates"
done

if [[ -z "$created" ]]; then
    if grep -q quotas_exceeded "$ERROR_LOG" 2>/dev/null; then
        cat >&2 <<'EOF'
error: refused with "quotas_exceeded" (quota 0): the account has no allowance
for that type yet — add & verify a payment method and/or request a quota
increase (console -> Organization -> Quotas -> Apple silicon).
EOF
        exit 1
    fi
    if grep -q out_of_stock "$ERROR_LOG" 2>/dev/null; then
        echo "no Apple Silicon stock in any zone right now — retry later (stock fluctuates)." >&2
        exit 3   # soft: distinguishes transient no-stock from real failures
    fi
    echo "error: every server type in every zone was refused; see errors above." >&2
    exit 1
fi
echo "created in zone $SCW_ZONE (remember it for delete: SCW_ZONE=$SCW_ZONE)"
server_id="$(echo "$created" | json 'd["id"]')"
echo "created server: $server_id"

echo "waiting for the server to become ready (Macs take a few minutes to boot)..."
ip=""
for _ in $(seq 1 90); do
    server="$(api GET "/zones/$SCW_ZONE/servers/$server_id")"
    status="$(echo "$server" | json 'd.get("status","")')"
    ip="$(echo "$server" | json 'd.get("ip","") or ""')"
    echo "  status=$status ip=${ip:-<none>}"
    if [[ "$status" == "ready" && -n "$ip" ]]; then break; fi
    sleep 20
done
if [[ "$status" != "ready" || -z "$ip" ]]; then
    echo "error: server did not become ready; inspect it in the Scaleway console" >&2
    echo "$server"
    exit 1
fi

ssh_user="$(echo "$server" | json 'd.get("ssh_username","") or "m1"')"
echo
echo "server ready: id=$server_id ip=$ip ssh=$ssh_user@$ip"
echo "(SSH uses the SSH keys registered in your Scaleway project.)"
echo
echo "REMEMBER: delete when done  ->  $0 delete $server_id"

if [[ -z "${GH_PAT:-}" ]]; then
    echo
    echo "GH_PAT not set — finish manually:"
    echo "  scp scripts/setup-macos-runner.sh $ssh_user@$ip:"
    echo "  ssh $ssh_user@$ip 'GH_PAT=<pat> GH_REPO=$GH_REPO bash setup-macos-runner.sh'"
    exit 0
fi

echo "registering GitHub Actions runner on the server..."
for _ in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$ssh_user@$ip" true 2>/dev/null; then
        break
    fi
    echo "  waiting for SSH..."
    sleep 20
done
scp -o StrictHostKeyChecking=accept-new "$SCRIPT_DIR/setup-macos-runner.sh" "$ssh_user@$ip":
ssh "$ssh_user@$ip" "GH_PAT='$GH_PAT' GH_REPO='$GH_REPO' bash setup-macos-runner.sh"
echo
echo "done — trigger the boot smoke with the 'vz metal boot smoke' workflow (workflow_dispatch)."
