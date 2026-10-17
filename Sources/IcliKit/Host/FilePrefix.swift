import Darwin
import Foundation

// Foundation only, so scripts/test-syslog.sh compiles it on the Mac.

/// The start of a regular file, read without loading the rest of it.
struct FilePrefix {
    var data: Data
    /// The whole file's size in bytes.
    var size: Int

    var truncated: Bool {
        data.count < size
    }

    /// Reads at most `limit` bytes, or the whole file without one. Refuses
    /// anything but a regular file, so a FIFO cannot block the read.
    static func read(_ path: String, limit: Int?) throws -> FilePrefix {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            throw FilePrefixError.open(String(cString: strerror(errno)))
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            throw FilePrefixError.notRegular
        }
        let size = Int(info.st_size)
        let wanted = min(size, limit ?? size)
        var data = Data(count: wanted)
        var filled = 0
        while filled < wanted {
            let count = data.withUnsafeMutableBytes { buffer in
                Darwin.read(fd, buffer.baseAddress! + filled, wanted - filled)
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else {
                throw FilePrefixError.read(String(cString: strerror(errno)))
            }
            if count == 0 { break }
            filled += count
        }
        data.count = filled
        return FilePrefix(data: data, size: max(size, filled))
    }

    /// `data` less an incomplete UTF-8 sequence at its end, where a byte
    /// limit may have cut one character in two.
    static func utf8Prefix(_ data: Data) -> Data {
        let bytes = [UInt8](data.suffix(4))
        // Walk back over continuation bytes to the last lead byte.
        var index = bytes.count - 1
        while index >= 0, bytes[index] & 0xC0 == 0x80 {
            index -= 1
        }
        guard index >= 0 else { return data }
        let lead = bytes[index]
        let length = lead < 0x80 ? 1 : lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1
        let present = bytes.count - index
        return present < length ? data.dropLast(present) : data
    }
}

enum FilePrefixError: Error {
    case open(String)
    case notRegular
    case read(String)

    var message: String {
        switch self {
        case let .open(reason): "cannot open the file: \(reason)"
        case .notRegular: "not a regular file"
        case let .read(reason): "cannot read the file: \(reason)"
        }
    }
}
