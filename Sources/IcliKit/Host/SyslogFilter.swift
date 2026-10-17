import Foundation

// Foundation only, so scripts/test-syslog.sh compiles it on the Mac.

/// What a unified log read keeps. Every field that is set narrows the read,
/// and each event is matched before anything counts it against a line cap,
/// so a filtered read is never starved by lines it would have dropped.
public struct SyslogFilter: Sendable, Hashable {
    /// The minimum levels icli accepts, from everything to faults only.
    /// `notice` and `default` are one level, the one icli reports as `notice`.
    public static let levels = ["all", "debug", "info", "default", "notice", "error", "fault"]
    /// The longest filter string, in UTF-8 bytes.
    public static let maximumFieldBytes = 1024

    /// A case-insensitive substring of the process name.
    public var process: String?
    /// The process identifier, exactly.
    public var pid: Int32?
    /// The subsystem or a dotted child of it: `com.example` keeps
    /// `com.example.net`, not `com.examples`.
    public var subsystem: String?
    /// The category, exactly.
    public var category: String?
    /// A case-sensitive substring of the message, such as a marker.
    public var messageContains: String?
    /// The minimum level, one of `levels`.
    public var level: String

    public init(
        process: String? = nil,
        pid: Int32? = nil,
        subsystem: String? = nil,
        category: String? = nil,
        messageContains: String? = nil,
        level: String = "all",
    ) {
        self.process = process
        self.pid = pid
        self.subsystem = subsystem
        self.category = category
        self.messageContains = messageContains
        self.level = level
    }

    /// Why the filter cannot be used, or nil. An empty string matches anything.
    public var problem: String? {
        guard Self.levels.contains(level) else {
            return "level must be one of " + Self.levels.joined(separator: ", ")
        }
        if let pid, pid <= 0 {
            return "pid must be positive"
        }
        for value in [process, subsystem, category, messageContains].compactMap(\.self) {
            if value.contains("\0") || value.utf8.count > Self.maximumFieldBytes {
                return "filters must be at most \(Self.maximumFieldBytes) bytes with no NUL"
            }
        }
        return nil
    }
}

/// One unified log entry.
public struct SyslogEntry: Sendable, Hashable {
    public var date: Date?
    public var process: String
    public var pid: Int32
    public var subsystem: String
    public var category: String
    /// `debug`, `info`, `notice`, `error` or `fault`.
    public var level: String
    public var message: String

    public init(
        date: Date?,
        process: String,
        pid: Int32,
        subsystem: String,
        category: String,
        level: String,
        message: String,
    ) {
        self.date = date
        self.process = process
        self.pid = pid
        self.subsystem = subsystem
        self.category = category
        self.level = level
        self.message = message
    }

    /// The entry in `log syslog`'s shape. The date keeps its fraction of a
    /// second here, where `log syslog` stamps whole seconds.
    public var jsonObject: [String: Any] {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return [
            "process": process,
            "pid": Int(pid),
            "message": message,
            "subsystem": subsystem,
            "category": category,
            "level": level,
            "date": date.map(formatter.string(from:)) ?? "",
        ]
    }
}

/// Why a `SyslogStream` ended.
public enum SyslogStreamEnd: String, Sendable {
    /// `cancel()`, or the stream was released.
    case cancelled
    /// Its `seconds` passed.
    case duration
    /// It delivered `maxEntries` entries.
    case entryLimit = "entry_limit"
    /// The handler answered false.
    case handler
    /// The system ended it: logd went away or refused this process.
    case interrupted
}
