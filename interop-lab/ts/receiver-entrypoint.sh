#!/bin/sh
# Start the reference receiver on a freshly minted identity.
#
# The keypair is generated here, at container start, and lives only in this
# process environment: no key material is committed, baked into an image layer,
# or shared between runs.
set -eu

node /app/dist/keygen.mjs > /tmp/receiver-identity.env
set -a
. /tmp/receiver-identity.env
set +a
rm -f /tmp/receiver-identity.env

exec node /app/server.mjs
