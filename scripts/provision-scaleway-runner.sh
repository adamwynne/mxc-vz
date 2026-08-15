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
        rm -f "$out"
        return 22
    fi
    cat "$out"
    rm -f "$out"
}

json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

if [[ "${1:-}" == "delete" ]]; then
    server_id="${2:?usage: $0 delete <server-id>}"
    echo "deleting server $server_id (fails if the 24h minimum has not elapsed)"
    api DELETE "/zones/$SCW_ZONE/servers/$server_id"
    echo "delete requested."
    exit 0
fi

: "${SCW_PROJECT_ID:?set SCW_PROJECT_ID to your Scaleway project ID}"

# Pick a server type: explicit override, else first type matching M4.
if [[ -z "${SCW_SERVER_TYPE:-}" ]]; then
    types_json="$(api GET "/zones/$SCW_ZONE/server-types")"
    echo "available server types in $SCW_ZONE:"
    echo "$types_json" | json 'chr(10).join(t["name"] for t in d["server_types"])'
    SCW_SERVER_TYPE="$(echo "$types_json" \
        | json 'next((t["name"] for t in d["server_types"] if "m4" in t["name"].lower()), "")')"
    if [[ -z "$SCW_SERVER_TYPE" ]]; then
        echo "error: no M4 type found in $SCW_ZONE; set SCW_SERVER_TYPE explicitly" >&2
        exit 1
    fi
fi
echo "using server type: $SCW_SERVER_TYPE"

echo
echo ">>> This allocation is billed for a MINIMUM OF 24 HOURS. Ctrl-C now to abort. <<<"
sleep 5

created="$(api POST "/zones/$SCW_ZONE/servers" "{
    \"name\": \"mxc-vz-runner\",
    \"project_id\": \"$SCW_PROJECT_ID\",
    \"type\": \"$SCW_SERVER_TYPE\"
}")"
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
