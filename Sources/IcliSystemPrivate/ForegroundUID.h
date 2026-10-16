#pragma once
#include <stdbool.h>
#include <stdint.h>

/// libxpc's foreground-uid lookup and its user-session predicate, as resolved
/// by dlsym: either may be NULL.
typedef uint64_t (*icli_foreground_uid_lookup)(uint64_t);
typedef bool (*icli_user_sessions_enabled)(void);

/// The foreground user's uid into `uid`, or false when there is none to ask
/// for. iOS 15 has no lookup. tvOS exports it but never enables user sessions,
/// and there the lookup traps with _xpc_api_misuse ("must not be called if
/// xpc_user_sessions_enabled() is false") rather than returning, so the
/// predicate is asked first whenever libxpc has it. Kept apart from Launchd.m
/// so scripts/test-foreground-uid.sh can check it on the Mac.
static inline bool icli_foreground_uid(icli_foreground_uid_lookup lookup, icli_user_sessions_enabled enabled, uint64_t *uid) {
    if (!lookup) return false;
    if (enabled && !enabled()) return false;
    *uid = lookup(0);
    return true;
}
