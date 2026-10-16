#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Host-side regression for the foreground-uid lookup on tvOS, where libxpc
# exports xpc_user_sessions_get_foreground_uid but traps in it while user
# sessions are off. Compiles the pure ForegroundUID.h against a stand-in that
# traps the same way, then checks nothing reaches the lookup around it.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
xcrun clang -std=c11 -Wall -Wextra -Werror -ISources/IcliSystemPrivate \
  Tests/ForegroundUID/main.c -o "$work/foreground-uid-tests"
"$work/foreground-uid-tests"

# Every use of the lookup goes through icli_foreground_uid: the symbol is only
# ever resolved by name, never linked or called directly.
direct="$(grep -rn 'xpc_user_sessions_get_foreground_uid' Sources | grep -v '^[^:]*:[0-9]*: *//' | grep -v 'dlsym(xpc, "xpc_user_sessions_get_foreground_uid")' || true)"
if [ -n "$direct" ]; then
  echo "FAIL: xpc_user_sessions_get_foreground_uid used outside the guarded dlsym:" >&2
  echo "$direct" >&2
  exit 1
fi
callers="$(grep -rn 'lookup(0)' Sources | grep -v 'ForegroundUID.h' || true)"
if [ -n "$callers" ]; then
  echo "FAIL: foreground-uid lookup called outside icli_foreground_uid:" >&2
  echo "$callers" >&2
  exit 1
fi
echo "foreground uid lookup: only through icli_foreground_uid"
