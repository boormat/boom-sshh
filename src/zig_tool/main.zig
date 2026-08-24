const std = @import("std");
const c = std.c;
const build_options = @import("build_options");

fn print_stdout(msg: []const u8) void {
    _ = c.write(c.STDOUT_FILENO, msg.ptr, msg.len);
}

pub fn main(minimal: std.process.Init.Minimal) !void {
    // 1. Get SSH_AUTH_SOCK from environment
    const sock_path = minimal.environ.getPosix("SSH_AUTH_SOCK") orelse {
        print_stdout("SSH_AUTH_SOCK not set\n");
        return error.EnvNotFound;
    };

    // 2. Collect args
    var args = minimal.args.iterate();
    _ = args.next(); // skip argv[0]

    // Count args and collect them
    var arg_list: [64][]const u8 = undefined;
    var arg_count: usize = 0;
    while (args.next()) |arg| {
        if (arg_count < arg_list.len) {
            arg_list[arg_count] = arg;
            arg_count += 1;
        }
    }

    if (arg_count == 0) {
        print_stdout("usage: boom-sshend <command...>\n");
        return error.MissingArgs;
    }

    // Check for version flags
    if (arg_count == 1 and (std.mem.eql(u8, arg_list[0], "version") or std.mem.eql(u8, arg_list[0], "--version") or std.mem.eql(u8, arg_list[0], "-V"))) {
        print_stdout("boom-sshend ");
        print_stdout(build_options.version);
        print_stdout("\n");
        return;
    }

    // 3. Auto-detect hostname, username/uid, pid
    var hostname_buf: [256]u8 = undefined;
    const hostname_len = c.gethostname(&hostname_buf, hostname_buf.len);
    const hostname: []const u8 = if (hostname_len == 0)
        std.mem.sliceTo(&hostname_buf, 0)
    else
        "unknown";

    // Get username, fall back to uid string if lookup fails
    const uid = c.getuid();
    const pw = c.getpwuid(uid);
    var uid_buf: [20]u8 = undefined;
    const user: []const u8 = if (pw) |p| blk: {
        if (p.name) |name| {
            break :blk std.mem.sliceTo(name, 0);
        }
        break :blk std.fmt.bufPrint(&uid_buf, "{}", .{uid}) catch "unknown";
    } else std.fmt.bufPrint(&uid_buf, "{}", .{uid}) catch "unknown";

    const ppid = c.getppid();

    // 4. Build payload: hostname user pid command
    var payload: [4096]u8 = undefined;
    const header = std.fmt.bufPrint(&payload, "{s} {s} {} ", .{ hostname, user, ppid }) catch return error.OutOfMemory;
    var pos = header.len;

    for (arg_list[0..arg_count]) |arg| {
        if (pos > header.len) {
            payload[pos] = ' ';
            pos += 1;
        }
        @memcpy(payload[pos..][0..arg.len], arg);
        pos += arg.len;
    }

    const payload_slice = payload[0..pos];

    // 4. Connect to Unix domain socket
    const fd = c.socket(c.AF.UNIX, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    defer _ = c.close(fd);

    var addr: c.sockaddr.un = .{
        .family = c.AF.UNIX,
        .path = undefined,
    };
    if (sock_path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..sock_path.len], sock_path);
    addr.path[sock_path.len] = 0;

    const addr_len: c.socklen_t = @intCast(@sizeOf(c.sockaddr.un) - addr.path.len + sock_path.len);
    const connect_result = c.connect(fd, @ptrCast(&addr), addr_len);
    if (connect_result != 0) return error.ConnectFailed;

    // 5. Build SSH_AGENTC_EXTENSION_REQUEST message
    const ext_type = "HISTORY";
    const msg_len: u32 = @intCast(1 + 4 + ext_type.len + payload_slice.len);

    var buf: [4 + 1 + 4 + 7 + 4096]u8 = undefined;
    var p: usize = 0;

    // Total length (big-endian uint32)
    std.mem.writeInt(u32, buf[p..][0..4], msg_len, .big);
    p += 4;

    // Message type: SSH_AGENTC_EXTENSION_REQUEST (27)
    buf[p] = 27;
    p += 1;

    // Extension type string: "HISTORY" (4-byte length prefix + bytes)
    std.mem.writeInt(u32, buf[p..][0..4], @intCast(ext_type.len), .big);
    p += 4;
    @memcpy(buf[p..][0..ext_type.len], ext_type);
    p += ext_type.len;

    // Payload (raw bytes, no length prefix — agent reads to EOF)
    @memcpy(buf[p..][0..payload_slice.len], payload_slice);
    p += payload_slice.len;

    // 6. Send
    const written = c.write(fd, buf[0..p].ptr, p);
    if (written < 0) return error.WriteFailed;
}

test "message wire format" {
    const ext_type = "HISTORY";
    const payload = "testhost 1000 1234   42  ls -la";
    const msg_len: u32 = @intCast(1 + 4 + ext_type.len + payload.len);

    var buf: [4 + 1 + 4 + 7 + 4096]u8 = undefined;
    var p: usize = 0;

    std.mem.writeInt(u32, buf[p..][0..4], msg_len, .big);
    p += 4;
    buf[p] = 27;
    p += 1;
    std.mem.writeInt(u32, buf[p..][0..4], @intCast(ext_type.len), .big);
    p += 4;
    @memcpy(buf[p..][0..ext_type.len], ext_type);
    p += ext_type.len;
    @memcpy(buf[p..][0..payload.len], payload);
    p += payload.len;

    // Verify
    try std.testing.expectEqual(@as(usize, 4 + 1 + 4 + 7 + payload.len), p);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 39 }, buf[0..4]);
    try std.testing.expectEqual(@as(u8, 27), buf[4]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 7 }, buf[5..9]);
    try std.testing.expectEqualSlices(u8, "HISTORY", buf[9..16]);
    try std.testing.expectEqualSlices(u8, payload, buf[16..16 + payload.len]);
}
