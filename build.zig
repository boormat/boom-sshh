const std = @import("std");

pub fn build(b: *std.Build) void {
    // Target list: Zig client targets (cross-compile from any host)
    const zig_targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
    };

    const zig_out_base = b.pathFromRoot("zig-out");

    // --- Step 1: Build histsend (Zig client) for all targets ---
    var zig_step = b.step("zig", "Build Zig client for all targets");

    for (zig_targets) |t| {
        const target = b.resolveTargetQuery(t);
        const triple = t.zigTriple(b.allocator) catch unreachable;

        const zig_mod = b.createModule(.{
            .root_source_file = b.path("src/zig_tool/main.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
            .link_libc = true,
        });

        const exe = b.addExecutable(.{
            .name = "histsend",
            .root_module = zig_mod,
        });

        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = triple } },
        });

        zig_step.dependOn(&install.step);
    }

    // --- Step 2: Build ssh-agent-history (Rust) for host only ---
    var rust_step = b.step("rust", "Build Rust agent for host target");

    const cargo_cmd = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
    });

    cargo_cmd.setEnvironmentVariable("PREBUILT_CLIENTS_DIR", zig_out_base);
    rust_step.dependOn(&cargo_cmd.step);

    // --- Default: build both ---
    b.default_step.dependOn(zig_step);
    b.default_step.dependOn(rust_step);
}

/// Convert Zig triple to Rust triple.
pub fn zigToRustTriple(zig_triple: []const u8) []const u8 {
    const map = [_]struct{ zig: []const u8, rust: []const u8 }{
        .{ .zig = "x86_64-linux-gnu", .rust = "x86_64-unknown-linux-gnu" },
        .{ .zig = "aarch64-linux-gnu", .rust = "aarch64-unknown-linux-gnu" },
        .{ .zig = "x86_64-linux-musl", .rust = "x86_64-unknown-linux-musl" },
        .{ .zig = "aarch64-linux-musl", .rust = "aarch64-unknown-linux-musl" },
        .{ .zig = "x86_64-macos", .rust = "x86_64-apple-darwin" },
        .{ .zig = "aarch64-macos", .rust = "aarch64-apple-darwin" },
        .{ .zig = "x86_64-windows-gnu", .rust = "x86_64-pc-windows-gnu" },
    };

    for (map) |entry| {
        if (std.mem.eql(u8, zig_triple, entry.zig)) return entry.rust;
    }
    return zig_triple;
}
