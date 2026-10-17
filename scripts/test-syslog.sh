#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Host-side regression for the unified log filters, which run before the line
# cap, and the stream's life cycle (cancel, limits, the system ending it).
# Compiles the real Logging.m against a stand-in stream.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
xcrun clang -fobjc-arc -fblocks -Wall -Wextra -Wno-unused-parameter -Werror \
  -ISources/IcliPrivate -ISources/IcliPrivate/include -ISources/IcliSystemPrivate/include -ISources/IcliLaunchPrivate/include \
  Sources/IcliPrivate/Logging.m Tests/Syslog/main.m -framework Foundation -o "$work/syslog-tests"
"$work/syslog-tests"
