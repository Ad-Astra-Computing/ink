#!/usr/bin/env bash
#
# One command: build the two lab images, start the four services on an isolated
# container network, run both drivers, print their assertions, tear everything
# down. Exits 0 when every assertion passed and 1 otherwise.
#
#   ./interop-lab/run.sh
#
# Engine selection: docker if present, otherwise podman. Override with
# INTEROP_LAB_ENGINE, which may carry flags, for example
# INTEROP_LAB_ENGINE="podman --storage-driver vfs".
#
# The lab network is created with --internal, so nothing inside it can reach
# anything outside it. Everything the exchange needs is in the images.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/.." && pwd)"

ENGINE="${INTEROP_LAB_ENGINE:-}"
if [ -z "${ENGINE}" ]; then
  if command -v docker >/dev/null 2>&1; then
    ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  else
    echo "interop-lab: no container engine found (looked for docker and podman)" >&2
    exit 2
  fi
fi

# ENGINE is deliberately unquoted at the call sites so an override may carry
# flags. Nothing user-supplied flows into it beyond that variable.
engine() {
  # shellcheck disable=SC2086
  ${ENGINE} "$@"
}

NETWORK=ink-interop-lab
TS_IMAGE=ink-interop-lab-ts:local
GO_IMAGE=ink-interop-lab-go:local
SERVICES=(ts-receiver ts-peer go-verifier go-peer)
DRIVERS=(go-driver ts-driver)

cleanup() {
  for name in "${SERVICES[@]}" "${DRIVERS[@]}"; do
    engine rm -f "ink-lab-${name}" >/dev/null 2>&1 || true
  done
  engine network rm "${NETWORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

dump_service_logs() {
  for name in "${SERVICES[@]}"; do
    echo
    echo "--- ink-lab-${name} logs ---"
    engine logs "ink-lab-${name}" 2>&1 | tail -40 || true
  done
}

echo "interop-lab: engine ${ENGINE}"
echo "interop-lab: building images"
engine build -f "${here}/ts/Dockerfile" -t "${TS_IMAGE}" "${repo}"
engine build -f "${here}/go/Dockerfile" -t "${GO_IMAGE}" "${repo}"

cleanup
echo "interop-lab: creating the isolated network"
engine network create --internal "${NETWORK}" >/dev/null

echo "interop-lab: starting services"
engine run -d --name ink-lab-ts-receiver --network "${NETWORK}" --network-alias ts-receiver \
  -e PORT=8787 -e INK_RECEIVER_HOST=ts-receiver.example \
  "${TS_IMAGE}" /app/receiver-entrypoint.sh >/dev/null

engine run -d --name ink-lab-ts-peer --network "${NETWORK}" --network-alias ts-peer \
  -e PORT=8790 "${TS_IMAGE}" node /app/dist/peer.mjs >/dev/null

engine run -d --name ink-lab-go-verifier --network "${NETWORK}" --network-alias go-verifier \
  --entrypoint /usr/local/bin/ink-verify-server "${GO_IMAGE}" -addr :8080 >/dev/null

engine run -d --name ink-lab-go-peer --network "${NETWORK}" --network-alias go-peer \
  --entrypoint /usr/local/bin/lab-peer "${GO_IMAGE}" -addr :8090 >/dev/null

# Each driver waits for the services it uses, so there is no sleep here.
echo
echo "interop-lab: running the exchange"
echo

go_status=0
engine run --rm --name ink-lab-go-driver --network "${NETWORK}" \
  --entrypoint /usr/local/bin/lab-driver "${GO_IMAGE}" || go_status=$?

echo

ts_status=0
engine run --rm --name ink-lab-ts-driver --network "${NETWORK}" \
  "${TS_IMAGE}" node /app/dist/driver.mjs || ts_status=$?

echo
if [ "${go_status}" -eq 0 ] && [ "${ts_status}" -eq 0 ]; then
  echo "interop-lab: PASS"
  exit 0
fi

echo "interop-lab: FAIL (go-driver exit ${go_status}, ts-driver exit ${ts_status})"
dump_service_logs
exit 1
