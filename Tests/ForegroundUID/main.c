// Host-side regression for the foreground-uid lookup guard: tvOS exports
// xpc_user_sessions_get_foreground_uid but traps in it while user sessions are
// off, so the guard must ask xpc_user_sessions_enabled first.
#include "ForegroundUID.h"
#include <stdio.h>
#include <stdlib.h>

static bool sessionsOn;
static int lookups;

// Stands in for libxpc: like tvOS, it traps when sessions are off.
static uint64_t lookup(uint64_t flags) {
    (void)flags;
    if (!sessionsOn) {
        fprintf(stderr, "FAIL: lookup called while user sessions are off\n");
        abort();
    }
    lookups++;
    return 501;
}

static bool enabled(void) {
    return sessionsOn;
}

static int failures;

static void expect(bool condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

int main(void) {
    uint64_t uid = 0;

    // iOS 15: no lookup at all.
    expect(!icli_foreground_uid(NULL, enabled, &uid), "no lookup gives no uid");

    // tvOS: lookup exported, sessions off. Must not reach the lookup.
    sessionsOn = false;
    lookups = 0;
    expect(!icli_foreground_uid(lookup, enabled, &uid), "sessions off gives no uid");
    expect(lookups == 0, "sessions off never calls the lookup");

    // iOS 16 and later: sessions on.
    sessionsOn = true;
    uid = 0;
    expect(icli_foreground_uid(lookup, enabled, &uid), "sessions on gives a uid");
    expect(uid == 501 && lookups == 1, "sessions on returns the lookup's uid");

    // A libxpc with the lookup but without the predicate keeps the old path.
    uid = 0;
    expect(icli_foreground_uid(lookup, NULL, &uid) && uid == 501, "no predicate keeps the lookup");

    if (failures) return 1;
    printf("foreground uid guard: ok\n");
    return 0;
}
