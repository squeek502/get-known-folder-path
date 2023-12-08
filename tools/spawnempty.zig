const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var empty_env = std.process.EnvMap.init(allocator);
    defer empty_env.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("no command to spawn", .{});
        std.process.exit(1);
    }

    const result = try std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = args[1..],
        .env_map = &empty_env,
        .max_output_bytes = std.math.maxInt(usize),
    });
    std.debug.print("{s}", .{result.stderr});
}
