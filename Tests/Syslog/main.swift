import Foundation

// The syslog filter's validation and the crash report's bounded read,
// checked on the Mac: compiles the Foundation-only SyslogFilter.swift and
// FilePrefix.swift on their own.

enum TestFailure: Error {
    case check(String)
}

func check(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw TestFailure.check(message) }
}

func filterProblems() throws {
    try check(SyslogFilter().problem == nil, "the empty filter is valid")
    for level in SyslogFilter.levels {
        try check(SyslogFilter(level: level).problem == nil, "level \(level) is valid")
    }
    try check(SyslogFilter(level: "verbose").problem != nil, "an unknown level is refused")
    try check(SyslogFilter(pid: 0).problem != nil, "pid 0 is refused")
    try check(SyslogFilter(subsystem: "a\0b").problem != nil, "a NUL is refused")
    try check(SyslogFilter(messageContains: String(repeating: "x", count: 1025)).problem != nil, "a long filter is refused")
    try check(SyslogFilter(messageContains: String(repeating: "x", count: 1024)).problem == nil, "1024 bytes is allowed")
    let entry = SyslogEntry(date: Date(timeIntervalSince1970: 1.25), process: "p", pid: 3, subsystem: "s", category: "c", level: "error", message: "m")
    let json = entry.jsonObject
    try check(JSONSerialization.isValidJSONObject(json), "an entry is JSON")
    try check((json["date"] as? String)?.contains(".250") == true, "the date keeps its fraction: \(json["date"] ?? "")")
    try check(SyslogEntry(date: nil, process: "", pid: 0, subsystem: "", category: "", level: "", message: "").jsonObject["date"] as? String == "", "no date")
}

func utf8Cut() throws {
    let text = "ab中🌱"
    let bytes = Data(text.utf8)
    for length in 0 ... bytes.count {
        let cut = FilePrefix.utf8Prefix(bytes.prefix(length))
        try check(String(data: cut, encoding: .utf8) != nil, "a cut at \(length) is whole characters")
        try check(length - cut.count < 4, "a cut drops at most three bytes")
    }
    try check(FilePrefix.utf8Prefix(bytes.prefix(5)).count == 5, "a whole character is kept")
    try check(FilePrefix.utf8Prefix(bytes.prefix(4)).count == 2, "half a character is dropped")
}

func boundedRead(_ directory: String) throws {
    let path = directory + "/report.ips"
    let text = String(repeating: "line 中\n", count: 1000)
    try text.write(toFile: path, atomically: true, encoding: .utf8)
    let size = text.utf8.count
    let whole = try FilePrefix.read(path, limit: nil)
    try check(whole.data.count == size && whole.size == size && !whole.truncated, "an unbounded read is the whole file")
    let bounded = try FilePrefix.read(path, limit: 100)
    try check(bounded.data.count == 100 && bounded.size == size && bounded.truncated, "a bounded read stops at its limit")
    let larger = try FilePrefix.read(path, limit: size * 2)
    try check(larger.data.count == size && !larger.truncated, "a limit above the size reads it all")
    do {
        _ = try FilePrefix.read(directory, limit: 10)
        try check(false, "a directory is refused")
    } catch FilePrefixError.notRegular {}
    let fifo = directory + "/fifo"
    try check(mkfifo(fifo, 0o600) == 0, "mkfifo")
    do {
        _ = try FilePrefix.read(fifo, limit: 10)
        try check(false, "a FIFO is refused")
    } catch FilePrefixError.notRegular {}
    do {
        _ = try FilePrefix.read(directory + "/missing.ips", limit: nil)
        try check(false, "a missing file is refused")
    } catch FilePrefixError.open {}
}

let directory = CommandLine.arguments[1]
do {
    try filterProblems()
    try utf8Cut()
    try boundedRead(directory)
    print("syslog filter validation and crash report reads: all checks passed")
} catch {
    FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
    exit(1)
}
