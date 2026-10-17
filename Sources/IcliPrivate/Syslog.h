#pragma once
#import <Foundation/Foundation.h>
#import "IcliPrivate.h"

NS_ASSUME_NONNULL_BEGIN

/// The minimum level a name keeps, as a rank from debug (0) to fault (4), or
/// -1 for a name icli does not accept. NULL is "all".
int icli_syslog_level_rank(const char *_Nullable level);

/// The rank of an os_log type: debug 0, info 1, default 2, error 3, fault 4.
/// A type icli does not know ranks with default.
int icli_syslog_type_rank(unsigned long long type);

/// icli's name for an os_log type, as `log syslog` reports it.
NSString *icli_syslog_severity(unsigned long long type);

/// What a syslog read keeps. Every set field narrows, and each event is
/// matched before anything counts it against a cap.
@interface IcliSyslogMatcher : NSObject
/// NULL or empty strings and a pid of 0 or less match anything. Nil when
/// `level` is not a name icli accepts.
- (nullable instancetype)initWithProcess:(const char *_Nullable)process
                                     pid:(int)pid
                               subsystem:(const char *_Nullable)subsystem
                                category:(const char *_Nullable)category
                         messageContains:(const char *_Nullable)message
                                   level:(const char *_Nullable)level;
/// Process: a case-insensitive substring of the name. Subsystem: that
/// subsystem or a dotted child of it (`a.b` keeps `a.b.c`, not `a.bc`).
/// Category: exact. Message: a case-sensitive substring.
- (BOOL)matchesProcess:(nullable NSString *)process
                   pid:(int)pid
             subsystem:(nullable NSString *)subsystem
              category:(nullable NSString *)category
                  type:(unsigned long long)type
               message:(nullable NSString *)message;
@end

/// One continuous listen on a live log stream: an `OSLogEventLiveStream`, or
/// anything else that answers `setEventHandler:`, `activate` and `invalidate`
/// with events that answer its properties.
///
/// Entries reach `entry` one at a time, in arrival order, under a lock that
/// `stop` also takes: once `stop` has returned, no entry arrives, whatever
/// thread called it, the entry handler's own included. `end` runs exactly
/// once, after the stream is invalidated, on a queue of its own.
@interface IcliSyslogStream : NSObject
- (instancetype)initWithStream:(id)stream
                       matcher:(IcliSyslogMatcher *)matcher
                    maxEntries:(long)maxEntries
                         entry:(IcliSyslogEntryHandler)entry
                           end:(nullable IcliSyslogEndHandler)end NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;
/// Activates the stream. With `seconds` above zero it ends by itself then.
- (void)startWithSeconds:(double)seconds;
/// Ends the listen; a second call does nothing.
- (void)stopWithReason:(IcliSyslogEnd)reason;
@property (readonly) long delivered;
@end

/// Listens on `stream` for `seconds` and answers `log syslog`'s result: the
/// matching entries, at most `maxLines` of them, and whether more matched.
NSDictionary *icli_syslog_capture(id stream, IcliSyslogMatcher *matcher, double seconds, int maxLines);

/// The live stream LoggingSupport offers this process, or nil.
id _Nullable icli_syslog_live_stream(void);

NS_ASSUME_NONNULL_END
