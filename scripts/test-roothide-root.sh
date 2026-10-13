#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Host-side regression for RootHide's root name rule and the lookup of a root
# on disk: compiles the plain C RootHideRoot.c on its own, so it needs nothing
# from the device or the package build.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
xcrun clang -Wall -Wextra -Werror -I Sources/IcliSystemPrivate/include \
  Tests/RootHideRoot/main.c Sources/IcliSystemPrivate/RootHideRoot.c \
  -o "$work/roothide-root-tests"
"$work/roothide-root-tests"
