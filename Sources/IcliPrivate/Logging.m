#import "IcliPrivate.h"
#import "Settle.h"
#import "IcliJSON.h"
#import "Syslog.h"
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <math.h>

// OSLogEventLiveStream is the diagnosticd live stream, not dmesg/history.
// The API was cross-checked against witchan/ios-mcp's MIT logreader.
static id logProperty(id event, NSString *name) {
    SEL selector = NSSelectorFromString(name);
    // Live events are forwarding proxies: respondsToSelector: returns NO for
    // properties that the proxy nevertheless implements through forwarding.
    return ((id (*)(id, SEL))objc_msgSend)(event, selector);
}

static NSString *stringOrNil(id value) {
    return [value isKindOfClass:NSString.class] ? value : nil;
}

static NSString *filterString(const char *value) {
    if (!value || !*value) return nil;
    return [NSString stringWithUTF8String:value];
}

int icli_syslog_level_rank(const char *level) {
    if (!level) return 0;
    NSDictionary<NSString *, NSNumber *> *ranks = @{
        @"all": @0, @"debug": @0, @"info": @1, @"default": @2, @"notice": @2, @"error": @3, @"fault": @4,
    };
    NSString *name = [NSString stringWithUTF8String:level];
    NSNumber *rank = name ? ranks[name] : nil;
    return rank ? rank.intValue : -1;
}

int icli_syslog_type_rank(unsigned long long type) {
    switch (type) {
    case 0x02: return 0;
    case 0x01: return 1;
    case 0x10: return 3;
    case 0x11: return 4;
    default: return 2;
    }
}

NSString *icli_syslog_severity(unsigned long long type) {
    switch (type) {
    case 0x00: return @"notice";
    case 0x01: return @"info";
    case 0x02: return @"debug";
    case 0x10: return @"error";
    case 0x11: return @"fault";
    default: return @"default";
    }
}

@implementation IcliSyslogMatcher {
    NSString *_process;
    int _pid;
    NSString *_subsystem;
    NSString *_subsystemChildren;
    NSString *_category;
    NSString *_message;
    int _rank;
}

- (instancetype)initWithProcess:(const char *)process
                            pid:(int)pid
                      subsystem:(const char *)subsystem
                       category:(const char *)category
                messageContains:(const char *)message
                          level:(const char *)level {
    int rank = icli_syslog_level_rank(level);
    if (rank < 0) return nil;
    if (!(self = [super init])) return nil;
    _process = filterString(process);
    _pid = pid > 0 ? pid : 0;
    _subsystem = filterString(subsystem);
    _subsystemChildren = [_subsystem stringByAppendingString:@"."];
    _category = filterString(category);
    _message = filterString(message);
    _rank = rank;
    return self;
}

- (BOOL)matchesProcess:(NSString *)process
                   pid:(int)pid
             subsystem:(NSString *)subsystem
              category:(NSString *)category
                  type:(unsigned long long)type
               message:(NSString *)message {
    if (icli_syslog_type_rank(type) < _rank) return NO;
    if (_pid && pid != _pid) return NO;
    if (_process && (!process || [process rangeOfString:_process options:NSCaseInsensitiveSearch].location == NSNotFound))
        return NO;
    if (_subsystem && !([subsystem isEqualToString:_subsystem] || [subsystem hasPrefix:_subsystemChildren])) return NO;
    if (_category && ![category isEqualToString:_category]) return NO;
    if (_message && (!message || [message rangeOfString:_message options:NSLiteralSearch].location == NSNotFound))
        return NO;
    return YES;
}

@end

@implementation IcliSyslogStream {
    id _stream;
    IcliSyslogMatcher *_matcher;
    long _maxEntries;
    IcliSyslogEntryHandler _entry;
    IcliSyslogEndHandler _end;
    // Recursive, so the entry handler may stop the stream it is called from.
    NSRecursiveLock *_lock;
    BOOL _finished;
    long _delivered;
}

- (instancetype)initWithStream:(id)stream
                       matcher:(IcliSyslogMatcher *)matcher
                    maxEntries:(long)maxEntries
                         entry:(IcliSyslogEntryHandler)entry
                           end:(IcliSyslogEndHandler)end {
    if (!(self = [super init])) return nil;
    _stream = stream;
    _matcher = matcher;
    _maxEntries = maxEntries > 0 ? maxEntries : 0;
    _entry = [entry copy];
    _end = [end copy];
    _lock = [NSRecursiveLock new];
    return self;
}

- (long)delivered {
    [_lock lock];
    long delivered = _delivered;
    [_lock unlock];
    return delivered;
}

- (void)startWithSeconds:(double)seconds {
    // The stream and the timer hold the listen weakly: whoever started it
    // keeps it, and a listen nobody keeps any more ends in dealloc.
    __weak IcliSyslogStream *weakSelf = self;
    void (^handler)(id) = ^(id event) {
        [weakSelf deliver:event];
    };
    ((void (*)(id, SEL, id))objc_msgSend)(_stream, NSSelectorFromString(@"setEventHandler:"), handler);
    SEL setInvalidation = NSSelectorFromString(@"setInvalidationHandler:");
    if ([_stream respondsToSelector:setInvalidation]) {
        // The handler's arguments are private and differ between releases;
        // a block that takes none ignores whatever the stream passes.
        void (^invalidated)(void) = ^{
            [weakSelf stopWithReason:IcliSyslogEndInterrupted];
        };
        ((void (*)(id, SEL, id))objc_msgSend)(_stream, setInvalidation, invalidated);
    }
    ((void (*)(id, SEL))objc_msgSend)(_stream, NSSelectorFromString(@"activate"));
    if (seconds > 0) {
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(seconds * NSEC_PER_SEC)),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
            ^{
                [weakSelf stopWithReason:IcliSyslogEndDuration];
            }
        );
    }
}

- (void)deliver:(id)event {
    @autoreleasepool {
        NSString *message = stringOrNil(logProperty(event, @"composedMessage"));
        if (!message) return;
        NSString *process = stringOrNil(logProperty(event, @"process"));
        NSString *subsystem = stringOrNil(logProperty(event, @"subsystem"));
        NSString *category = stringOrNil(logProperty(event, @"category"));
        unsigned long long type = ((unsigned long long (*)(id, SEL))objc_msgSend)(event, NSSelectorFromString(@"logType"));
        int pid = ((int (*)(id, SEL))objc_msgSend)(event, NSSelectorFromString(@"processIdentifier"));
        if (![_matcher matchesProcess:process pid:pid subsystem:subsystem category:category type:type message:message])
            return;
        id date = logProperty(event, @"date");
        double seconds = [date isKindOfClass:NSDate.class] ? [(NSDate *)date timeIntervalSince1970] : NAN;
        [_lock lock];
        if (_finished) {
            [_lock unlock];
            return;
        }
        bool more = _entry(
            (process ?: @"").UTF8String,
            pid,
            (subsystem ?: @"").UTF8String,
            (category ?: @"").UTF8String,
            icli_syslog_severity(type).UTF8String,
            message.UTF8String,
            seconds
        );
        _delivered++;
        BOOL limit = _maxEntries && _delivered >= _maxEntries;
        [_lock unlock];
        if (!more) {
            [self stopWithReason:IcliSyslogEndStopped];
        } else if (limit) {
            [self stopWithReason:IcliSyslogEndEntryLimit];
        }
    }
}

- (void)stopWithReason:(IcliSyslogEnd)reason {
    [_lock lock];
    if (_finished) {
        [_lock unlock];
        return;
    }
    _finished = YES;
    long delivered = _delivered;
    [_lock unlock];
    // Invalidated off this thread: the caller may be the stream's own handler.
    id stream = _stream;
    IcliSyslogEndHandler end = _end;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        ((void (*)(id, SEL))objc_msgSend)(stream, NSSelectorFromString(@"invalidate"));
        if (end) end(reason, delivered);
    });
}

- (void)dealloc {
    if (!_finished) {
        ((void (*)(id, SEL))objc_msgSend)(_stream, NSSelectorFromString(@"invalidate"));
        if (_end) _end(IcliSyslogEndCancelled, _delivered);
    }
}

@end

id icli_syslog_live_stream(void) {
    dlopen("/System/Library/PrivateFrameworks/LoggingSupport.framework/LoggingSupport", RTLD_NOW);
    Class streamClass = NSClassFromString(@"OSLogEventLiveStream");
    id stream = streamClass ? [[streamClass alloc] init] : nil;
    if (!stream
        || ![stream respondsToSelector:NSSelectorFromString(@"setEventHandler:")]
        || ![stream respondsToSelector:NSSelectorFromString(@"activate")]
        || ![stream respondsToSelector:NSSelectorFromString(@"invalidate")]) {
        return nil;
    }
    return stream;
}

NSDictionary *icli_syslog_capture(id live, IcliSyslogMatcher *matcher, double seconds, int maxLines) {
    NSMutableArray *entries = [NSMutableArray array];
    NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
    __block BOOL truncated = NO;
    // Entries arrive one at a time under the stream's lock, and the stop
    // below takes that lock, so the array needs no lock of its own.
    IcliSyslogStream *stream = [[IcliSyslogStream alloc]
        initWithStream:live
               matcher:matcher
            maxEntries:0
                 entry:^bool(const char *name, int pid, const char *subsystem, const char *category,
                             const char *severity, const char *message, double date) {
                     if (entries.count >= (NSUInteger)maxLines) {
                         truncated = YES;
                         return true;
                     }
                     NSDate *stamp = isnan(date) ? nil : [NSDate dateWithTimeIntervalSince1970:date];
                     [entries addObject:@{
                         @"process": @(name),
                         @"pid": @(pid),
                         @"message": @(message),
                         @"subsystem": @(subsystem),
                         @"category": @(category),
                         @"level": @(severity),
                         @"date": stamp ? [formatter stringFromDate:stamp] : @""
                     }];
                     return true;
                 }
                   end:nil];
    [stream startWithSeconds:0];
    // The stream calls the handler on its own queue; this only waits.
    icli_settle(seconds);
    [stream stopWithReason:IcliSyslogEndDuration];
    NSArray *snapshot = [entries copy];
    return @{
        @"entries": snapshot,
        @"count": @(snapshot.count),
        @"truncated": @(truncated),
        @"source": @"unified_log",
        @"seconds": @(seconds)
    };
}

char *icli_syslog_json(
    double seconds,
    const char *process,
    int pid,
    const char *subsystem,
    const char *category,
    const char *message_contains,
    const char *level,
    int max_lines
) {
    IcliSyslogMatcher *matcher = [[IcliSyslogMatcher alloc] initWithProcess:process
                                                                        pid:pid
                                                                  subsystem:subsystem
                                                                   category:category
                                                            messageContains:message_contains
                                                                      level:level];
    if (!matcher) return icli_json(@{@"error": @"unknown log level"});
    id live = icli_syslog_live_stream();
    if (!live) return icli_json(@{@"error": @"unified log stream unavailable"});
    return icli_json(icli_syslog_capture(live, matcher, seconds, max_lines));
}

void *icli_syslog_stream_open(
    const char *process,
    int pid,
    const char *subsystem,
    const char *category,
    const char *message_contains,
    const char *level,
    double seconds,
    long max_entries,
    IcliSyslogEntryHandler entry,
    IcliSyslogEndHandler end
) {
    IcliSyslogMatcher *matcher = [[IcliSyslogMatcher alloc] initWithProcess:process
                                                                        pid:pid
                                                                  subsystem:subsystem
                                                                   category:category
                                                            messageContains:message_contains
                                                                      level:level];
    id live = matcher && entry ? icli_syslog_live_stream() : nil;
    if (!live) return NULL;
    IcliSyslogStream *stream = [[IcliSyslogStream alloc] initWithStream:live
                                                                matcher:matcher
                                                             maxEntries:max_entries
                                                                  entry:entry
                                                                    end:end];
    [stream startWithSeconds:seconds];
    return (void *)CFBridgingRetain(stream);
}

void icli_syslog_stream_cancel(void *stream) {
    if (stream) [(__bridge IcliSyslogStream *)stream stopWithReason:IcliSyslogEndCancelled];
}

void icli_syslog_stream_release(void *stream) {
    if (!stream) return;
    icli_syslog_stream_cancel(stream);
    CFBridgingRelease(stream);
}
