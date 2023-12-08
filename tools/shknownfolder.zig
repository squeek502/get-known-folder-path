const std = @import("std");
const os = std.os;
const known_folder = @import("known_folder");
const KnownFolder = known_folder.KnownFolder;

pub extern "shell32" fn SHGetKnownFolderPath(
    rfid: *const os.windows.KNOWNFOLDERID,
    dwFlags: os.windows.DWORD,
    hToken: ?os.windows.HANDLE,
    ppszPath: *[*:0]os.windows.WCHAR,
) callconv(os.windows.WINAPI) os.windows.HRESULT;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        const values = std.enums.values(KnownFolder);
        for (values) |folder| {
            var dir_path_ptr: [*:0]u16 = undefined;
            switch (SHGetKnownFolderPath(
                &folder.getMetadata().id,
                os.windows.KF_FLAG_DONT_VERIFY,
                null,
                &dir_path_ptr,
            )) {
                os.windows.S_OK => {
                    const dir_path = std.mem.sliceTo(dir_path_ptr, 0);
                    if (dir_path[0] == '%') {
                        std.debug.print("{s}: {}\n", .{ @tagName(folder), std.unicode.fmtUtf16le(dir_path) });
                    }
                },
                os.windows.E_FAIL => {},
                else => |err| {
                    std.debug.print("{s}: error: {x} ({})\n", .{ @tagName(folder), @as(c_ulong, @bitCast(err)), std.os.windows.HRESULT_CODE(err) });
                },
            }
        }
        return;
    }

    const folder = std.meta.stringToEnum(KnownFolder, args[1]) orelse {
        std.debug.print("unknown folder: {s}\n", .{args[1]});
        std.process.exit(1);
    };

    var dir_path_ptr: [*:0]u16 = undefined;
    switch (SHGetKnownFolderPath(
        &folder.getMetadata().id,
        os.windows.KF_FLAG_DONT_VERIFY,
        null,
        &dir_path_ptr,
    )) {
        os.windows.S_OK => {
            const global_dir = std.unicode.utf16leToUtf8Alloc(allocator, std.mem.sliceTo(dir_path_ptr, 0)) catch |err| switch (err) {
                error.UnexpectedSecondSurrogateHalf => return error.AppDataDirUnavailable,
                error.ExpectedSecondSurrogateHalf => return error.AppDataDirUnavailable,
                error.DanglingSurrogateHalf => return error.AppDataDirUnavailable,
                error.OutOfMemory => return error.OutOfMemory,
            };
            defer allocator.free(global_dir);
            std.debug.print("{s}\n", .{global_dir});
        },
        os.windows.E_OUTOFMEMORY => return error.OutOfMemory,
        else => |err| {
            std.debug.print("{}\n", .{std.os.windows.HRESULT_CODE(err)});
            return error.DirNotFound;
        },
    }
}
