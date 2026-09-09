#!/usr/bin/env sh
# The negative controls, kept in the tree they run against: the release leg of
# the workflow checks out a release and runs it, so a control list held in the
# workflow would be a command line from one tree handed to another.
#
# Two surfaces, because the fault is injected per surface. Two fault kinds,
# because a wrong answer and no answer take different comparison paths.

set -eu

node differential/run.mjs --self-test private-hostname --cases 200
node differential/run.mjs --self-test signature-base --cases 200
node differential/run.mjs --self-test signature-base --drop --cases 200
