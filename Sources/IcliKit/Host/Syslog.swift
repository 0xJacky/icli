import Foundation
import IcliPrivate
import IcliSystem

/// Listens to the live unified log for `seconds` and answers what matched,
/// at most `maxLines` entries; `truncated` says more matched. Every filter
/// applies before the cap.
public func captureSyslog(
    seconds: TimeInterval,
    process: String? = nil,
    level: String = "all",
    maxLines: Int = 500,
    subsystem: String? = nil,
    category: String? = nil,
    messageContains: String? = nil,
    pid: Int32? = nil,
) throws -> [String: Any] {
    try captureSyslog(
        seconds: seconds,
        filter: SyslogFilter(
            process: process,
            pid: pid,
            subsystem: subsystem,
            category: category,
            messageContains: messageContains,
            level: level,
        ),
        maxLines: maxLines,
    )
}

public func captureSyslog(seconds: TimeInterval, filter: SyslogFilter, maxLines: Int = 500) throws -> [String: Any] {
    guard seconds.isFinite, (0.1 ... 60).contains(seconds), (1 ... 5000).contains(maxLines) else {
        throw IcliError.failed("seconds must be 0.1–60 and max-lines 1–5000")
    }
    if let problem = filter.problem {
        throw IcliError.failed(problem)
    }
    return try decodeBridgeJSON(
        takeCString(icli_syslog_json(
            seconds,
            filter.process,
            filter.pid ?? 0,
            filter.subsystem,
            filter.category,
            filter.messageContains,
            filter.level,
            Int32(maxLines),
        )),
        "unified log response",
    )
}

/// One continuous listen on the live unified log, with no seam in it: every
/// matching entry reaches `handler`, one at a time and in arrival order, from
/// the moment `init` returns until the stream ends.
///
/// It ends after `seconds` (when given), after `maxEntries` entries (when
/// given), when `handler` answers false, when the system ends it, or at
/// `cancel()`; `onEnd` then runs once, on a queue of its own. Once `cancel()`
/// has returned no entry arrives, whichever thread called it, `handler`
/// included. Releasing the stream cancels it.
///
/// Nothing is buffered here: a slow handler holds up the stream, and the
/// system drops what it cannot hold rather than this process growing. Do not
/// make `handler` wait on a thread that may be calling `cancel()`.
public final class SyslogStream: @unchecked Sendable {
    public static let secondsRange: ClosedRange<TimeInterval> = 0.1 ... 86400
    public static let maxEntriesRange: ClosedRange<Int> = 1 ... 1_000_000

    private let handle: UnsafeMutableRawPointer
    private let state: State

    public init(
        filter: SyslogFilter = SyslogFilter(),
        seconds: TimeInterval? = nil,
        maxEntries: Int? = nil,
        handler: @escaping @Sendable (SyslogEntry) -> Bool,
        onEnd: (@Sendable (SyslogStreamEnd) -> Void)? = nil,
    ) throws {
        if let problem = filter.problem {
            throw IcliError.failed(problem)
        }
        if let seconds, !(seconds.isFinite && Self.secondsRange.contains(seconds)) {
            throw IcliError.failed("seconds must be 0.1–86400")
        }
        if let maxEntries, !Self.maxEntriesRange.contains(maxEntries) {
            throw IcliError.failed("max-entries must be 1–1000000")
        }
        let state = State(onEnd: onEnd)
        let entry: IcliSyslogEntryHandler = { process, pid, subsystem, category, level, message, date in
            handler(SyslogEntry(
                date: date.isNaN ? nil : Date(timeIntervalSince1970: date),
                process: process.map { String(cString: $0) } ?? "",
                pid: pid,
                subsystem: subsystem.map { String(cString: $0) } ?? "",
                category: category.map { String(cString: $0) } ?? "",
                level: level.map { String(cString: $0) } ?? "",
                message: message.map { String(cString: $0) } ?? "",
            ))
        }
        let end: IcliSyslogEndHandler = { reason, _ in
            state.finish(SyslogStreamEnd(reason))
        }
        guard let handle = icli_syslog_stream_open(
            filter.process,
            filter.pid ?? 0,
            filter.subsystem,
            filter.category,
            filter.messageContains,
            filter.level,
            seconds ?? 0,
            maxEntries ?? 0,
            entry,
            end,
        ) else {
            throw IcliError.unavailable("unified log stream unavailable")
        }
        self.handle = handle
        self.state = state
    }

    deinit {
        icli_syslog_stream_release(handle)
    }

    /// Stops the stream now. A second call does nothing.
    public func cancel() {
        icli_syslog_stream_cancel(handle)
    }

    /// Why the stream ended, or nil while it runs.
    public var end: SyslogStreamEnd? {
        state.current
    }

    /// Blocks until the stream has ended and answers why, or nil when
    /// `timeout` seconds pass first.
    @discardableResult
    public func wait(timeout: TimeInterval? = nil) -> SyslogStreamEnd? {
        state.wait(until: timeout.map { Date(timeIntervalSinceNow: $0) })
    }

    private final class State: @unchecked Sendable {
        private let condition = NSCondition()
        private var reason: SyslogStreamEnd?
        private let onEnd: (@Sendable (SyslogStreamEnd) -> Void)?

        init(onEnd: (@Sendable (SyslogStreamEnd) -> Void)?) {
            self.onEnd = onEnd
        }

        var current: SyslogStreamEnd? {
            condition.lock()
            defer { condition.unlock() }
            return reason
        }

        func finish(_ end: SyslogStreamEnd) {
            condition.lock()
            guard reason == nil else {
                condition.unlock()
                return
            }
            reason = end
            condition.broadcast()
            condition.unlock()
            onEnd?(end)
        }

        func wait(until deadline: Date?) -> SyslogStreamEnd? {
            condition.lock()
            defer { condition.unlock() }
            while reason == nil {
                if let deadline {
                    if !condition.wait(until: deadline) { break }
                } else {
                    condition.wait()
                }
            }
            return reason
        }
    }
}

private extension SyslogStreamEnd {
    init(_ reason: IcliSyslogEnd) {
        switch reason {
        case IcliSyslogEndDuration: self = .duration
        case IcliSyslogEndEntryLimit: self = .entryLimit
        case IcliSyslogEndStopped: self = .handler
        case IcliSyslogEndInterrupted: self = .interrupted
        default: self = .cancelled
        }
    }
}

/// The live unified log as an async sequence: one `SyslogStream` that ends
/// with the sequence, when the consuming task is cancelled, or when the
/// stream ends by itself. At most `bufferLimit` entries wait for a consumer
/// that falls behind; later ones are dropped until it catches up.
public func syslogEntries(
    filter: SyslogFilter = SyslogFilter(),
    seconds: TimeInterval? = nil,
    maxEntries: Int? = nil,
    bufferLimit: Int = 1000,
) throws -> AsyncStream<SyslogEntry> {
    guard bufferLimit > 0 else {
        throw IcliError.failed("buffer limit must be positive")
    }
    let (entries, continuation) = AsyncStream.makeStream(of: SyslogEntry.self, bufferingPolicy: .bufferingOldest(bufferLimit))
    let stream = try SyslogStream(
        filter: filter,
        seconds: seconds,
        maxEntries: maxEntries,
        handler: { entry in
            if case .terminated = continuation.yield(entry) { return false }
            return true
        },
        onEnd: { _ in continuation.finish() },
    )
    // The sequence keeps the stream until it terminates either way.
    continuation.onTermination = { _ in stream.cancel() }
    return entries
}
