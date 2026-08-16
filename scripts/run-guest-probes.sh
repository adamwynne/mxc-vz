#!/bin/bash
# Run a directory of sentinel probes against a live guest agent.
#
# Usage: run-guest-probes.sh <addr> <probes-dir>
#   addr        agent TCP address, e.g. 127.0.0.1:7777
#   probes-dir  directory of <name>.json (vz policy whose process.commandLine
#               IS the probe) + <name>.expect (sentinel contract)
#
# The .expect contract, one entry per line:
#   exitcode:<n>   (optional, FIRST line only) expected remote exit code;
#                  defaults to 0 when absent
#   <sentinel>     required: must appear in the probe's stdout
#   !<sentinel>    forbidden: must NOT appear in the probe's stdout
#   # comment / blank lines are ignored
#
# A <name>.reject marker next to the .json marks a validation-only probe
# (the policy must be REJECTED by vz_validate; there is nothing to execute)
# — such probes are skipped here and covered by the CI validation step.
#
# Environment overrides:
#   EXEC_TCP    path to the exec_tcp example (default target/debug/examples/exec_tcp)
#   RETRY_SECS  exec_tcp retry budget in seconds (default 60)
#
# Must run under bash 3.2 (macOS): no associative arrays, no mapfile, and
# `set -u` + empty-array expansion is avoided entirely (see build-mac.sh).
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <addr> <probes-dir>" >&2
    exit 2
fi
ADDR="$1"
PROBES_DIR="$2"

cd "$(dirname "$0")/.."

EXEC_TCP="${EXEC_TCP:-target/debug/examples/exec_tcp}"
RETRY_SECS="${RETRY_SECS:-60}"

if [ ! -x "$EXEC_TCP" ]; then
    echo "error: $EXEC_TCP not found or not executable — build it first:" >&2
    echo "  cargo build -p vz_protocol --example exec_tcp" >&2
    exit 2
fi
if [ ! -d "$PROBES_DIR" ]; then
    echo "error: probes dir not found: $PROBES_DIR" >&2
    exit 2
fi
if ! ls "$PROBES_DIR"/*.json >/dev/null 2>&1; then
    echo "error: no *.json probes in $PROBES_DIR" >&2
    exit 2
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/mxc-probes.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

# Results are accumulated as newline-separated "name<TAB>verdict<TAB>detail"
# rows in a plain string (bash 3.2: no arrays needed, no set -u pitfalls).
results=""
failures=0
ran=0

for json in "$PROBES_DIR"/*.json; do
    name="$(basename "$json" .json)"
    base="${json%.json}"
    expect="$base.expect"

    if [ -e "$base.reject" ]; then
        results="${results}${name}	SKIP	validation-only probe (.reject marker; covered by vz_validate CI step)
"
        continue
    fi
    if [ ! -f "$expect" ]; then
        results="${results}${name}	FAIL	missing $name.expect
"
        failures=$((failures + 1))
        continue
    fi

    command_line="$(python3 -c 'import json, sys
print(json.load(open(sys.argv[1]))["process"]["commandLine"])' "$json")" || {
        results="${results}${name}	FAIL	cannot extract process.commandLine
"
        failures=$((failures + 1))
        continue
    }

    stdout_file="$WORKDIR/$name.stdout"
    stderr_file="$WORKDIR/$name.stderr"
    set +e
    "$EXEC_TCP" "$ADDR" "$command_line" "$RETRY_SECS" \
        > "$stdout_file" 2> "$stderr_file"
    code=$?
    set -e
    ran=$((ran + 1))

    # Parse the .expect contract.
    expected_code=0
    first_line="$(head -n 1 "$expect" 2>/dev/null || true)"
    case "$first_line" in
        exitcode:*) expected_code="${first_line#exitcode:}" ;;
    esac

    problems=""
    if [ "$code" != "$expected_code" ]; then
        problems="${problems}exit=$code (want $expected_code); "
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*|exitcode:*) continue ;;
            '!'*)
                sentinel="${line#!}"
                if grep -F -q -- "$sentinel" "$stdout_file"; then
                    problems="${problems}forbidden '$sentinel' present; "
                fi
                ;;
            *)
                if ! grep -F -q -- "$line" "$stdout_file"; then
                    problems="${problems}missing '$line'; "
                fi
                ;;
        esac
    done < "$expect"

    if [ -z "$problems" ]; then
        results="${results}${name}	PASS	exit=$code
"
    else
        results="${results}${name}	FAIL	${problems}
"
        failures=$((failures + 1))
        echo "--- $name: probe stdout ---"
        sed 's/^/    /' "$stdout_file" | head -50
        if [ -s "$stderr_file" ]; then
            echo "--- $name: exec_tcp stderr ---"
            sed 's/^/    /' "$stderr_file" | head -20
        fi
    fi
done

echo
echo "== probe results ($PROBES_DIR against $ADDR) =="
printf '%s' "$results" | while IFS='	' read -r name verdict detail; do
    printf '%-28s %-5s %s\n' "$name" "$verdict" "$detail"
done
echo

if [ "$failures" -ne 0 ]; then
    echo "FAILED: $failures probe(s) failed ($ran executed)"
    exit 1
fi
echo "OK: all $ran executed probe(s) passed"
