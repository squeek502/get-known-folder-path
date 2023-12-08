const std = @import("std");
const known_folder = @import("known_folder.zig");
const KnownFolder = known_folder.KnownFolder;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        const values = std.enums.values(KnownFolder);
        for (values) |folder| {
            const path_space = known_folder.getPath(folder) catch |err| switch (err) {
                error.VirtualFolder => continue,
                else => {
                    std.debug.print("{s}: error: {s}\n", .{ @tagName(folder), @errorName(err) });
                    continue;
                },
            };
            if (path_space.data[0] == '%') {
                std.debug.print("{s}: {}\n", .{ @tagName(folder), std.unicode.fmtUtf16le(path_space.span()) });
            }
        }
        return;
    }

    const folder = std.meta.stringToEnum(KnownFolder, args[1]) orelse {
        std.debug.print("unknown folder: {s}\n", .{args[1]});
        std.process.exit(1);
    };

    const path = try known_folder.getPath(folder);
    std.debug.print("{}\n", .{std.unicode.fmtUtf16le(path.span())});
}
