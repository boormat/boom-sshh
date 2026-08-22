pub const Target = struct {
    zig_triple: []const u8,
    rust_triple: []const u8,
    bin_suffix: []const u8,
};

pub const targets = [_]Target{
    .{ .zig_triple = "x86_64-linux-musl", .rust_triple = "x86_64-unknown-linux-musl", .bin_suffix = "linux-x86_64" },
    .{ .zig_triple = "aarch64-linux-musl", .rust_triple = "aarch64-unknown-linux-musl", .bin_suffix = "linux-aarch64" },
    .{ .zig_triple = "x86_64-macos", .rust_triple = "x86_64-apple-darwin", .bin_suffix = "darwin-x86_64" },
    .{ .zig_triple = "aarch64-macos", .rust_triple = "aarch64-apple-darwin", .bin_suffix = "darwin-aarch64" },
};
