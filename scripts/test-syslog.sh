#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Host-side regression for the unified log filters, which run before the line
# cap, the stream's life cycle (cancel, limits, the system ending it) and the
# crash report's bounded read. Compiles the real Logging.m against a stand-in
# stream, and the Foundation-only Swift files on their own.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
xcrun clang -fobjc-arc -fblocks -Wall -Wextra -Wno-unused-parameter -Werror \
  -ISources/IcliPrivate -ISources/IcliPrivate/include -ISources/IcliSystemPrivate/include -ISources/IcliLaunchPrivate/include \
  Sources/IcliPrivate/Logging.m Tests/Syslog/main.m -framework Foundation -o "$work/syslog-tests"
"$work/syslog-tests"
xcrun swiftc -swift-version 6 -module-cache-path "$work/modules" \
  Tests/Syslog/main.swift Sources/IcliKit/Host/SyslogFilter.swift Sources/IcliKit/Host/FilePrefix.swift \
  -o "$work/syslog-swift-tests"
mkdir "$work/files"
"$work/syslog-swift-tests" "$work/files"
