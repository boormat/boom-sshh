const std = @import("std");
const cfg = @import("targets.zig");

pub fn build(b: *std.Build) void {
    const zig_out_base = b.pathFromRoot("zig-out");

    // --- Target option for agent build ---
    const resolved_target = b.standardTargetOptions(.{});
    const is_native = resolved_target.query.isNative();

    // --- Step 1: Build Zig clients for all targets ---
    var zig_step = b.step("zig", "Build Zig client for all targets");

    inline for (cfg.targets) |t| {
        const query = std.Target.Query.parse(.{ .arch_os_abi = t.zig_triple }) catch
            @panic("invalid zig triple in targets.zig: " ++ t.zig_triple);
        const resolved = b.resolveTargetQuery(query);
        const triple = query.zigTriple(b.allocator) catch unreachable;

        const zig_mod = b.createModule(.{
            .root_source_file = b.path("src/zig_tool/main.zig"),
            .target = resolved,
            .optimize = .ReleaseSmall,
            .link_libc = true,
        });

        const exe = b.addExecutable(.{
            .name = "boom-sshend",
            .root_module = zig_mod,
        });

        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = triple } },
        });

        zig_step.dependOn(&install.step);
    }

    // --- Step 2: Build Rust agent ---
    var rust_step = b.step("rust", "Build Rust agent");

    const rust_triple: []const u8 = if (is_native)
        ""
    else
        findRustTriple(resolved_target.query) orelse
            @panic("target not found in targets.zig: pass one of the supported zig triples");

    const cargo_args: []const []const u8 = if (is_native)
        &.{ "cargo", "zigbuild", "--release" }
    else
        &.{ "cargo", "zigbuild", "--release", "--target", rust_triple };

    const cargo_cmd = b.addSystemCommand(cargo_args);
    cargo_cmd.setEnvironmentVariable("PREBUILT_CLIENTS_DIR", zig_out_base);
    rust_step.dependOn(zig_step);
    rust_step.dependOn(&cargo_cmd.step);

    // --- Step 3: List supported targets ---
    const targets_buf = comptime blk: {
        var buf: []const u8 = "";
        for (cfg.targets) |t| {
            buf = buf ++ t.zig_triple ++ " " ++ t.rust_triple ++ " " ++ t.bin_suffix ++ "\n";
        }
        break :blk buf;
    };
    const echo_cmd = b.addSystemCommand(&.{ "printf", "%s", targets_buf });
    var targets_step = b.step("targets", "List supported build targets");
    targets_step.dependOn(&echo_cmd.step);

    // --- Default: build both ---
    b.default_step.dependOn(zig_step);
    b.default_step.dependOn(rust_step);
}

/// Match the user-provided target query against our known targets by comparing
/// cpu_arch, os_tag, and abi fields (avoids string-roundtrip issues with zigTriple).
fn findRustTriple(query: std.Target.Query) ?[]const u8 {
    inline for (cfg.targets) |t| {
        const known = std.Target.Query.parse(.{ .arch_os_abi = t.zig_triple }) catch unreachable;
        if (query.cpu_arch == known.cpu_arch and query.os_tag == known.os_tag and
            query.abi == known.abi)
            return t.rust_triple;
    }
    return null;
}
