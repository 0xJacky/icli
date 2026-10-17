#import <Foundation/Foundation.h>
#import <stdatomic.h>
#import "Syslog.h"

// The syslog filters and the stream's life cycle, checked on the Mac against
// a stand-in for OSLogEventLiveStream that answers the same selectors.

static int failures;
#define CHECK(condition, ...) do { if (!(condition)) { failures++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

@interface FakeEvent : NSObject
@property (copy) NSString *composedMessage;
@property (copy) NSString *process;
@property (copy) NSString *subsystem;
@property (copy) NSString *category;
@property unsigned long long logType;
@property int processIdentifier;
@property (copy) NSDate *date;
@end
@implementation FakeEvent
@end

static FakeEvent *event(NSString *process, int pid, NSString *subsystem, NSString *category, unsigned long long type, NSString *message) {
    FakeEvent *e = [FakeEvent new];
    e.process = process;
    e.processIdentifier = pid;
    e.subsystem = subsystem;
    e.category = category;
    e.logType = type;
    e.composedMessage = message;
    e.date = [NSDate date];
    return e;
}

/// Plays `events` from its own thread, then keeps sending noise until it is
/// invalidated, as the live stream does.
@interface FakeStream : NSObject
@property (copy) void (^eventHandler)(id);
@property (copy) void (^invalidationHandler)(void);
@property (copy) NSArray<FakeEvent *> *events;
@property (atomic) BOOL invalidated;
@property (atomic) int invalidations;
@property (atomic) BOOL noise;
@end
@implementation FakeStream
- (void)activate {
    void (^handler)(id) = self.eventHandler;
    NSArray *events = self.events;
    [NSThread detachNewThreadWithBlock:^{
        for (FakeEvent *e in events) {
            if (self.invalidated) return;
            handler(e);
        }
        while (self.noise && !self.invalidated) {
            handler(event(@"noise", 9, @"com.example.noise", @"n", 0, @"noise"));
            usleep(200);
        }
    }];
}
- (void)invalidate {
    self.invalidated = YES;
    self.invalidations++;
    if (self.invalidationHandler) self.invalidationHandler();
}
/// The system ending the stream on its own.
- (void)dropConnection {
    self.invalidated = YES;
    if (self.invalidationHandler) self.invalidationHandler();
}
@end

static IcliSyslogMatcher *matcher(const char *process, int pid, const char *subsystem, const char *category, const char *message, const char *level) {
    return [[IcliSyslogMatcher alloc] initWithProcess:process pid:pid subsystem:subsystem category:category messageContains:message level:level];
}

static BOOL matches(IcliSyslogMatcher *m, FakeEvent *e) {
    return [m matchesProcess:e.process pid:e.processIdentifier subsystem:e.subsystem category:e.category type:e.logType message:e.composedMessage];
}

static void filters(void) {
    FakeEvent *net = event(@"SpringBoard", 50, @"com.example.net", @"http", 0x10, @"Marker-42 loaded");
    CHECK(matches(matcher(NULL, 0, NULL, NULL, NULL, NULL), net), "no filter keeps everything");
    CHECK(matches(matcher("", 0, "", "", "", "all"), net), "empty strings match anything");
    CHECK(matches(matcher(NULL, 0, "com.example", NULL, NULL, NULL), net), "a dotted child matches its subsystem");
    CHECK(matches(matcher(NULL, 0, "com.example.net", NULL, NULL, NULL), net), "the subsystem itself matches");
    CHECK(!matches(matcher(NULL, 0, "com.exam", NULL, NULL, NULL), net), "a bare prefix is not a parent");
    CHECK(!matches(matcher(NULL, 0, "com.example.net.http", NULL, NULL, NULL), net), "a child does not match its parent");
    CHECK(matches(matcher(NULL, 0, NULL, "http", NULL, NULL), net), "category exact");
    CHECK(!matches(matcher(NULL, 0, NULL, "htt", NULL, NULL), net), "category is not a substring");
    CHECK(matches(matcher(NULL, 0, NULL, NULL, "Marker-42", NULL), net), "message substring");
    CHECK(!matches(matcher(NULL, 0, NULL, NULL, "marker-42", NULL), net), "message is case-sensitive");
    CHECK(matches(matcher("springb", 0, NULL, NULL, NULL, NULL), net), "process is a case-insensitive substring");
    CHECK(!matches(matcher("backboardd", 0, NULL, NULL, NULL, NULL), net), "another process");
    CHECK(matches(matcher(NULL, 50, NULL, NULL, NULL, NULL), net) && !matches(matcher(NULL, 51, NULL, NULL, NULL, NULL), net), "pid exact");
    CHECK(!matches(matcher(NULL, 0, "com.example", NULL, NULL, NULL), event(@"x", 1, nil, nil, 0, @"m")), "no subsystem fails a subsystem filter");

    unsigned long long types[] = {0x02, 0x01, 0x00, 0x10, 0x11};
    const char *levels[] = {"debug", "info", "default", "error", "fault"};
    for (int level = 0; level < 5; level++) {
        for (int type = 0; type < 5; type++) {
            BOOL kept = matches(matcher(NULL, 0, NULL, NULL, NULL, levels[level]), event(@"p", 1, @"s", @"c", types[type], @"m"));
            CHECK(kept == (type >= level), "level %s and type %llx", levels[level], types[type]);
        }
    }
    CHECK(matches(matcher(NULL, 0, NULL, NULL, NULL, "notice"), event(@"p", 1, @"s", @"c", 0, @"m")), "notice is default");
    CHECK(!matches(matcher(NULL, 0, NULL, NULL, NULL, "error"), event(@"p", 1, @"s", @"c", 0x40, @"m")), "an unknown type ranks with default");
    CHECK(matcher(NULL, 0, NULL, NULL, NULL, "verbose") == nil, "an unknown level is refused");
    CHECK([icli_syslog_severity(0) isEqualToString:@"notice"] && [icli_syslog_severity(0x11) isEqualToString:@"fault"], "severity names");
}

/// A read capped at a few lines still finds the marker behind a flood of
/// unrelated lines: the filters run before the cap.
static void filtersBeforeTheCap(void) {
    NSMutableArray *events = [NSMutableArray array];
    for (int i = 0; i < 2000; i++) [events addObject:event(@"noise", 9, @"com.example.noise", @"n", 0x10, @"unrelated")];
    [events addObject:event(@"Target", 77, @"com.example.tweak", @"load", 0, @"Marker-42 loaded")];
    for (int i = 0; i < 2000; i++) [events addObject:event(@"noise", 9, @"com.example.noise", @"n", 0x10, @"unrelated")];
    FakeStream *stream = [FakeStream new];
    stream.events = events;
    NSDictionary *result = icli_syslog_capture(stream, matcher(NULL, 0, "com.example.tweak", NULL, "Marker-42", NULL), 1.0, 5);
    NSArray *entries = result[@"entries"];
    CHECK(entries.count == 1 && [entries[0][@"message"] isEqual:@"Marker-42 loaded"], "marker found behind the flood: %s", result.description.UTF8String);
    CHECK([result[@"truncated"] isEqual:@NO], "one match is not truncated");
    CHECK([entries.firstObject[@"pid"] isEqual:@77] && [entries.firstObject[@"level"] isEqual:@"notice"], "entry fields");
    // The stream is invalidated off the caller's thread, just after.
    for (int i = 0; i < 200 && !stream.invalidated; i++) usleep(5000);
    CHECK(stream.invalidations == 1, "capture invalidates its stream once");

    stream = [FakeStream new];
    stream.events = events;
    result = icli_syslog_capture(stream, matcher("noise", 0, NULL, NULL, NULL, "error"), 1.0, 5);
    CHECK([result[@"count"] isEqual:@5] && [result[@"truncated"] isEqual:@YES], "the cap counts matches and says truncated");
}

typedef struct {
    atomic_long entries;
    atomic_int ends;
    atomic_int reason;
} Counters;

static IcliSyslogStream *openListen(FakeStream *fake, IcliSyslogMatcher *m, long maxEntries, Counters *counters, bool (^body)(long count)) {
    return [[IcliSyslogStream alloc] initWithStream:fake matcher:m maxEntries:maxEntries
        entry:^bool(const char *p, int pid, const char *s, const char *c, const char *l, const char *msg, double date) {
            long count = atomic_fetch_add(&counters->entries, 1) + 1;
            return body ? body(count) : true;
        }
        end:^(IcliSyslogEnd reason, long delivered) {
            atomic_store(&counters->reason, reason);
            atomic_fetch_add(&counters->ends, 1);
        }];
}

static void waitForEnd(Counters *counters) {
    for (int i = 0; i < 400 && atomic_load(&counters->ends) == 0; i++) usleep(5000);
}

static void lifecycle(void) {
    IcliSyslogMatcher *all = matcher(NULL, 0, NULL, NULL, NULL, NULL);

    // Cancelled from another thread: nothing arrives once stop returns.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        fake.noise = YES;
        __attribute__((objc_precise_lifetime)) IcliSyslogStream *stream = openListen(fake, all, 0, &counters, nil);
        [stream startWithSeconds:0];
        while (atomic_load(&counters.entries) < 50) usleep(1000);
        [stream stopWithReason:IcliSyslogEndCancelled];
        long atStop = atomic_load(&counters.entries);
        usleep(50000);
        waitForEnd(&counters);
        CHECK(atomic_load(&counters.entries) == atStop, "entries after cancel: %ld then %ld", atStop, atomic_load(&counters.entries));
        CHECK(atomic_load(&counters.ends) == 1 && atomic_load(&counters.reason) == IcliSyslogEndCancelled, "one cancelled end");
        [stream stopWithReason:IcliSyslogEndCancelled];
        usleep(20000);
        CHECK(atomic_load(&counters.ends) == 1 && fake.invalidations == 1, "a second stop does nothing");
    }
    // Stopped from inside the handler: no deadlock, nothing more.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        fake.noise = YES;
        __block IcliSyslogStream *stream;
        stream = openListen(fake, all, 0, &counters, ^bool(long count) {
            if (count == 10) [stream stopWithReason:IcliSyslogEndCancelled];
            return true;
        });
        [stream startWithSeconds:0];
        waitForEnd(&counters);
        usleep(20000);
        CHECK(atomic_load(&counters.entries) == 10, "stop inside the handler: %ld entries", atomic_load(&counters.entries));
        CHECK(atomic_load(&counters.reason) == IcliSyslogEndCancelled, "reason cancelled");
        stream = nil;
    }
    // The handler answers false.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        fake.noise = YES;
        __attribute__((objc_precise_lifetime)) IcliSyslogStream *stream = openListen(fake, all, 0, &counters, ^bool(long count) { return count < 7; });
        [stream startWithSeconds:0];
        waitForEnd(&counters);
        usleep(20000);
        CHECK(atomic_load(&counters.entries) == 7 && atomic_load(&counters.reason) == IcliSyslogEndStopped, "handler stop: %ld", atomic_load(&counters.entries));
        CHECK(stream.delivered == 7, "delivered counts what reached the handler");
    }
    // The entry limit, counting matches only.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        NSMutableArray *events = [NSMutableArray array];
        for (int i = 0; i < 100; i++) [events addObject:event(@"p", 1, i % 2 ? @"com.example.a" : @"com.example.b", @"c", 0, @"m")];
        fake.events = events;
        __attribute__((objc_precise_lifetime)) IcliSyslogStream *stream = openListen(fake, matcher(NULL, 0, "com.example.a", NULL, NULL, NULL), 20, &counters, nil);
        [stream startWithSeconds:0];
        waitForEnd(&counters);
        usleep(20000);
        CHECK(atomic_load(&counters.entries) == 20 && atomic_load(&counters.reason) == IcliSyslogEndEntryLimit, "entry limit: %ld", atomic_load(&counters.entries));
    }
    // The duration.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        fake.noise = YES;
        __attribute__((objc_precise_lifetime)) IcliSyslogStream *stream = openListen(fake, all, 0, &counters, nil);
        NSDate *start = [NSDate date];
        [stream startWithSeconds:0.3];
        waitForEnd(&counters);
        NSTimeInterval took = -start.timeIntervalSinceNow;
        CHECK(atomic_load(&counters.reason) == IcliSyslogEndDuration && took >= 0.29 && took < 1.5, "duration end after %.2f s", took);
        CHECK(fake.invalidated, "the duration invalidates the stream");
        (void)stream;
    }
    // The system ends the stream.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        fake.noise = YES;
        __attribute__((objc_precise_lifetime)) IcliSyslogStream *stream = openListen(fake, all, 0, &counters, nil);
        [stream startWithSeconds:0];
        usleep(20000);
        [fake dropConnection];
        waitForEnd(&counters);
        CHECK(atomic_load(&counters.reason) == IcliSyslogEndInterrupted && atomic_load(&counters.ends) == 1, "interrupted end");
        (void)stream;
    }
    // A listen nobody keeps any more ends.
    {
        Counters counters = {0};
        FakeStream *fake = [FakeStream new];
        fake.noise = YES;
        @autoreleasepool {
            __attribute__((objc_precise_lifetime)) IcliSyslogStream *stream = openListen(fake, all, 0, &counters, nil);
            [stream startWithSeconds:0];
            usleep(20000);
        }
        usleep(20000);
        long after = atomic_load(&counters.entries);
        usleep(20000);
        CHECK(fake.invalidated && atomic_load(&counters.ends) == 1 && atomic_load(&counters.reason) == IcliSyslogEndCancelled, "released listen is cancelled");
        CHECK(atomic_load(&counters.entries) == after, "nothing after release");
    }
}

int main(void) {
    @autoreleasepool {
        filters();
        filtersBeforeTheCap();
        lifecycle();
    }
    if (failures) {
        fprintf(stderr, "%d syslog check(s) failed\n", failures);
        return 1;
    }
    puts("syslog filters and stream: all checks passed");
    return 0;
}
