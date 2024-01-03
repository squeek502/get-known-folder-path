const std = @import("std");
const misc = @import("misc.zig");
const windows = std.os.windows;
const GUID = windows.GUID;
const L = misc.unicode.asciiToUtf16LeStringLiteral;

const GetPathError = error{ PathTooLong, PathNotFound, VirtualFolder, Unexpected };

/// Retrieves the full path of a known folder identified by the folder's KNOWNFOLDERID.
/// Always returns the known folder for the current user.
/// Does not verify that the path returned exists on the filesystem.
pub fn getPath(folder: KnownFolder) GetPathError!windows.PathSpace {
    const metadata = folder.getMetadata();

    // Virtual folders do not have an associated path.
    // SHGetKnownFolderPath returns E_FAIL for these paths.
    if (metadata.category == .virtual) return error.VirtualFolder;
    // Special case for folders that always error with 'file not found' for unknown reasons.
    // See the 'sample_playlists' initialization in known_folder_metadata for an example.
    if (metadata.category == .not_found) return error.PathNotFound;

    // Create a stack of all the parent directories
    const folder_stack = init: {
        // Because the parents for each known folder are known and fixed, we know that the maximum
        // number of folders needed to resolve any known folder path is 5 (`startup`).
        var stack: [5]KnownFolder = undefined;
        var cur_depth: usize = 0;
        var cur_folder: KnownFolder = folder;
        while (true) : (cur_depth += 1) {
            stack[cur_depth] = cur_folder;
            cur_folder = cur_folder.getMetadata().parent orelse break;
        }
        break :init stack[0 .. cur_depth + 1];
    };
    var registry = LazyRegistry{};
    defer registry.deinit();

    const unexpanded_path = (try getUserShellFoldersPath(folder_stack, &registry)) orelse
        (try getDefaultPath(folder_stack, &registry));
    return expandPath(unexpanded_path.span(), &registry);
}

fn getUserShellFoldersPath(folder_stack: []const KnownFolder, registry: *LazyRegistry) GetPathError!?windows.PathSpace {
    var path: windows.PathSpace = .{ .data = undefined, .len = 0 };

    // Find the first folder in the stack that has a 'User Shell Folders' entry
    var i: usize = 0;
    while (i < folder_stack.len) : (i += 1) {
        const folder = folder_stack[i];
        const metadata = folder.getMetadata();
        // Fixed paths are not affected by redirection via User Shell Folders, only
        // 'common' and 'per user' paths are checked for redirection.
        if (metadata.category == .fixed) return null;

        // If there is a path in User Shell Folders, then that is the path that should be used.
        const user_shell_key = switch (metadata.category) {
            .peruser => registry.getHKCUUserShellFoldersKey() catch |err| switch (err) {
                error.FileNotFound => return null,
                else => |e| return e,
            },
            .common => registry.getHKLMUserShellFoldersKey() catch |err| switch (err) {
                error.FileNotFound => return null,
                else => |e| return e,
            },
            else => unreachable,
        };
        var value_type: windows.DWORD = undefined;
        var value_byte_len: windows.DWORD = path.data.len * 2;
        const buf = std.mem.sliceAsBytes(&path.data);
        const guid_string = misc.windows.GUID.stringifyW(metadata.id);
        const query_result = windows.advapi32.RegQueryValueExW(
            user_shell_key,
            if (metadata.reg_name) |reg_name| reg_name else &guid_string,
            null,
            &value_type,
            @ptrCast(buf.ptr),
            &value_byte_len,
        );
        switch (@as(windows.Win32Error, @enumFromInt(query_result))) {
            .SUCCESS => {
                const code_unit_len = value_byte_len / 2 - 1;
                path.len = code_unit_len;
                switch (value_type) {
                    windows.REG.SZ => {},
                    windows.REG.EXPAND_SZ => {
                        path = try expandPath(path.span(), registry);
                    },
                    else => continue,
                }
                break;
            },
            .MORE_DATA => return error.PathTooLong,
            else => continue,
        }
    }

    // Now traverse backwards and append defaults of any paths that were traversed past.
    while (i > 0) {
        i -= 1;
        const default_path = folder_stack[i].getMetadata().default_path.?;

        if (path.len + 1 > path.data.len) return error.PathTooLong;
        path.data[path.len] = '\\';
        path.len += 1;
        if (path.len + default_path.len > path.data.len) return error.PathTooLong;
        @memcpy(path.data[path.len..][0..default_path.len], default_path);
        path.len += default_path.len;
    }

    path.data[path.len] = 0;

    return path;
}

fn getDefaultPath(folder_stack: []const KnownFolder, registry: *LazyRegistry) GetPathError!windows.PathSpace {
    var path: windows.PathSpace = .{ .data = undefined, .len = 0 };

    // Traverse backwards from the 'innermost' parent to the 'outermost' child to
    // construct the path.
    var path_buf = std.ArrayListUnmanaged(u16).initBuffer(&path.data);
    var i: usize = folder_stack.len - 1;
    while (true) : (i -= 1) {
        const cur_folder = folder_stack[i];
        const cur_metadata = cur_folder.getMetadata();

        if (cur_metadata.default_path) |default_path| {
            if (cur_metadata.parent != null) {
                if (path_buf.items.len + 1 > path.data.len) return error.PathTooLong;
                path_buf.appendAssumeCapacity('\\');
            }
            if (path_buf.items.len + default_path.len > path.data.len) return error.PathTooLong;
            path_buf.appendSliceAssumeCapacity(default_path);
        } else {
            switch (cur_metadata.category) {
                // Fixed paths are guaranteed to be at the start ('outermost' parent) of the path.
                // This means that there's no chance of overflowing the path data when appending
                // fixed paths of a known length.
                .fixed => {
                    switch (cur_folder) {
                        .system => {
                            const unused_slice = path_buf.unusedCapacitySlice();
                            const written_code_units = misc.windows.kernel32.GetSystemDirectoryW(@ptrCast(unused_slice), @intCast(unused_slice.len));
                            if (written_code_units == 0) {
                                switch (windows.kernel32.GetLastError()) {
                                    else => |err| return windows.unexpectedError(err),
                                }
                            }
                            if (written_code_units > unused_slice.len) return error.PathTooLong;
                            path_buf.items.len += written_code_units;
                        },
                        .system_x86 => {
                            const unused_slice = path_buf.unusedCapacitySlice();
                            var written_code_units = misc.windows.kernel32.GetSystemWow64DirectoryW(@ptrCast(unused_slice), @intCast(unused_slice.len));
                            // Wow64 directory does not exist if the kernel is 32-bit, in which case
                            // we fallback to the normal system directory.
                            if (written_code_units == 0) {
                                written_code_units = misc.windows.kernel32.GetSystemDirectoryW(@ptrCast(unused_slice), @intCast(unused_slice.len));
                                if (written_code_units == 0) {
                                    switch (windows.kernel32.GetLastError()) {
                                        else => |err| return windows.unexpectedError(err),
                                    }
                                }
                            }
                            if (written_code_units > unused_slice.len) return error.PathTooLong;
                            path_buf.items.len += written_code_units;
                        },
                        .program_files,
                        .program_files_common,
                        .program_files_x86,
                        .program_files_common_x86,
                        => {
                            const unused_slice = path_buf.unusedCapacitySlice();
                            const current_version_key = registry.getHKLMCurrentVersionKey() catch |err| switch (err) {
                                error.FileNotFound => return error.PathNotFound,
                                else => |e| return e,
                            };
                            const value = getRegistryStringValue(unused_slice, current_version_key, cur_metadata.reg_name.?) catch |err| switch (err) {
                                // Returning an error when the value in CurrentVersion is not found matches
                                // the behavior of SHGetKnownFolderPath.
                                error.FileNotFound => return error.PathNotFound,
                                error.BufferTooSmall => return error.PathTooLong,
                                error.NotAString => return error.PathNotFound,
                                error.Unexpected => |e| return e,
                            };
                            path_buf.items.len += value.len;
                        },
                        .program_files_x64,
                        .program_files_common_x64,
                        => {
                            var system_processor_info: misc.windows.SYSTEM_PROCESSOR_INFORMATION = undefined;
                            switch (windows.ntdll.NtQuerySystemInformation(
                                misc.windows.SystemProcessorInformationEnum(),
                                &system_processor_info,
                                @sizeOf(misc.windows.SYSTEM_PROCESSOR_INFORMATION),
                                null,
                            )) {
                                .SUCCESS => {},
                                else => |err| return windows.unexpectedStatus(err),
                            }
                            // If the processor architecture is 32-bit, then there is no
                            // x64 directory.
                            switch (system_processor_info.ProcessorArchitecture) {
                                misc.windows.PROCESSOR_ARCHITECTURE_ARM,
                                misc.windows.PROCESSOR_ARCHITECTURE_INTEL,
                                => return error.PathNotFound,
                                // Assume anything other than the known 32-bit architectures
                                // are 64-bit.
                                else => {},
                            }
                            const unused_slice = path_buf.unusedCapacitySlice();
                            const current_version_key = registry.getHKLMCurrentVersionKey() catch |err| switch (err) {
                                error.FileNotFound => return error.PathNotFound,
                                else => |e| return e,
                            };
                            const value = getRegistryStringValue(unused_slice, current_version_key, cur_metadata.reg_name.?) catch |err| switch (err) {
                                // Returning a 'not found' error when the value in CurrentVersion
                                // is not found matches the behavior of SHGetKnownFolderPath.
                                error.FileNotFound => return error.PathNotFound,
                                error.BufferTooSmall => return error.PathTooLong,
                                error.NotAString => return error.PathNotFound,
                                error.Unexpected => |e| return e,
                            };
                            path_buf.items.len += value.len;
                        },
                        .resource_dir => {
                            path_buf.appendSliceAssumeCapacity(L("%WINDIR%\\resources"));
                        },
                        .localized_resources_dir => {
                            // TODO: This may not fully match the behavior of SHGetKnownFolderPath, as
                            //       SHGetKnownFolderPath seems to do some registry lookups like
                            //       Software\Policies\Microsoft\MUI\Settings, which GetUserDefaultLangID
                            //       does not seem to do. However, GetUserDefaultLangID does return
                            //       the appropriate value for the language in the scenarios that have
                            //       been tested so far.
                            const langid = misc.windows.kernel32.GetUserDefaultLangID();
                            path_buf.appendSliceAssumeCapacity(L("%WINDIR%\\resources\\"));
                            var hex_buf: [4]u8 = undefined;
                            const formatted = std.fmt.bufPrint(&hex_buf, "{x:0>4}", .{langid}) catch unreachable;
                            for (formatted) |c| {
                                path_buf.appendAssumeCapacity(c);
                            }
                        },
                        .user_profiles => {
                            const unused_slice = path_buf.unusedCapacitySlice();
                            const profile_list_key = registry.getHKLMProfileListKey() catch |err| switch (err) {
                                error.FileNotFound => return error.PathNotFound,
                                else => |e| return e,
                            };
                            const value = getRegistryStringValue(unused_slice, profile_list_key, cur_metadata.reg_name.?) catch |err| switch (err) {
                                // Returning a 'not found' error when the value in CurrentVersion
                                // is not found matches the behavior of SHGetKnownFolderPath.
                                error.FileNotFound => return error.PathNotFound,
                                error.BufferTooSmall => return error.PathTooLong,
                                error.NotAString => return error.PathNotFound,
                                error.Unexpected => |e| return e,
                            };
                            path_buf.items.len += value.len;
                        },
                        .program_data => {
                            path_buf.appendSliceAssumeCapacity(L("%ProgramData%"));
                        },
                        .windows => {
                            path_buf.appendSliceAssumeCapacity(L("%WINDIR%"));
                        },
                        .public => {
                            path_buf.appendSliceAssumeCapacity(L("%PUBLIC%"));
                        },
                        .profile => {
                            path_buf.appendSliceAssumeCapacity(L("%USERPROFILE%"));
                        },
                        else => unreachable,
                    }
                },
                else => unreachable, // Anything non-fixed *must* have a default path
            }
        }

        if (i == 0) break;
    }

    path.data[path_buf.items.len] = 0;
    path.len = path_buf.items.len;
    return path;
}

const LazyRegistry = struct {
    hklm_current_version: ?windows.HKEY = null,
    hklm_profile_list: ?windows.HKEY = null,
    hkcu_user_shell_folders: ?windows.HKEY = null,
    hklm_user_shell_folders: ?windows.HKEY = null,

    pub fn deinit(self: LazyRegistry) void {
        if (self.hklm_current_version) |key| {
            _ = std.os.windows.advapi32.RegCloseKey(key);
        }
        if (self.hklm_profile_list) |key| {
            _ = std.os.windows.advapi32.RegCloseKey(key);
        }
        if (self.hkcu_user_shell_folders) |key| {
            _ = std.os.windows.advapi32.RegCloseKey(key);
        }
        if (self.hklm_user_shell_folders) |key| {
            _ = std.os.windows.advapi32.RegCloseKey(key);
        }
    }

    pub fn getHKLMCurrentVersionKey(self: *LazyRegistry) !windows.HKEY {
        if (self.hklm_current_version == null) {
            self.hklm_current_version = try openKey(
                windows.HKEY_LOCAL_MACHINE,
                L("SOFTWARE\\Microsoft\\Windows\\CurrentVersion"),
            );
        }
        return self.hklm_current_version.?;
    }

    pub fn getHKLMProfileListKey(self: *LazyRegistry) !windows.HKEY {
        if (self.hklm_profile_list == null) {
            self.hklm_profile_list = try openKey(
                windows.HKEY_LOCAL_MACHINE,
                L("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
            );
        }
        return self.hklm_profile_list.?;
    }

    pub fn getHKCUUserShellFoldersKey(self: *LazyRegistry) !windows.HKEY {
        if (self.hkcu_user_shell_folders == null) {
            self.hkcu_user_shell_folders = try openKey(
                misc.windows.HKEY_CURRENT_USER,
                L("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"),
            );
        }
        return self.hkcu_user_shell_folders.?;
    }

    pub fn getHKLMUserShellFoldersKey(self: *LazyRegistry) !windows.HKEY {
        if (self.hklm_user_shell_folders == null) {
            self.hklm_user_shell_folders = try openKey(
                windows.HKEY_LOCAL_MACHINE,
                L("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"),
            );
        }
        return self.hklm_user_shell_folders.?;
    }

    fn openKey(root_key: windows.HKEY, key_path: [:0]const u16) !windows.HKEY {
        var key: windows.HKEY = undefined;
        const open_result = std.os.windows.advapi32.RegOpenKeyExW(
            root_key,
            key_path,
            0,
            windows.KEY_QUERY_VALUE,
            &key,
        );
        switch (@as(windows.Win32Error, @enumFromInt(open_result))) {
            .SUCCESS => {
                return key;
            },
            .FILE_NOT_FOUND => return error.FileNotFound,
            else => |err| return windows.unexpectedError(err),
        }
    }
};

/// Returns error.NotAString if the value if not of type REG_SZ/REG_EXPAND_SZ
fn getRegistryStringValue(
    value_buf: []u16,
    key: windows.HKEY,
    value_name: [:0]const u16,
) ![:0]u16 {
    var value_type: windows.DWORD = undefined;
    var value_size: windows.DWORD = @intCast(value_buf.len * 2);
    const buf = std.mem.sliceAsBytes(value_buf);
    const query_result = windows.advapi32.RegQueryValueExW(
        key,
        value_name,
        null,
        &value_type,
        @ptrCast(buf.ptr),
        &value_size,
    );
    switch (@as(windows.Win32Error, @enumFromInt(query_result))) {
        .SUCCESS => {
            switch (value_type) {
                windows.REG.SZ, windows.REG.EXPAND_SZ => {},
                else => return error.NotAString,
            }
            const code_unit_len = value_size / 2 - 1;
            // RegQueryValueExW does not guarantee that the values
            // returned are NUL-terminated, so force NUL-termination.
            value_buf[code_unit_len] = 0;
            return value_buf[0..code_unit_len :0];
        },
        .FILE_NOT_FOUND => return error.FileNotFound,
        .MORE_DATA => return error.BufferTooSmall,
        else => |err| return windows.unexpectedError(err),
    }
}

const UnexpandedIterator = struct {
    buffer: []const u16,
    index: ?usize = 0,

    /// Returns either a slice containing an unexpanded environment variable, in which
    /// case the returned slice with start and end with '%', or a slice without any
    /// unexpanded environment variables.
    ///
    /// For example, "foo/%bar%/baz" will return "foo/", "%bar%", "/baz", null in that order.
    pub fn next(self: *UnexpandedIterator) ?[]const u16 {
        const start = self.index orelse return null;
        const starts_with_percent = self.buffer[start] == '%';
        const search_start = if (starts_with_percent) start + 1 else start;
        const end = if (std.mem.indexOfScalarPos(u16, self.buffer, search_start, '%')) |before_percent| blk: {
            if (starts_with_percent) {
                const after_percent = before_percent + 1;
                self.index = if (after_percent < self.buffer.len) after_percent else null;
                break :blk after_percent;
            } else {
                self.index = before_percent;
                break :blk before_percent;
            }
        } else blk: {
            self.index = null;
            break :blk self.buffer.len;
        };
        return self.buffer[start..end];
    }
};

test UnexpandedIterator {
    {
        var it = UnexpandedIterator{ .buffer = L("a/b/%cde%/f/%ghi%") };
        try std.testing.expectEqualSlices(u16, L("a/b/"), it.next().?);
        try std.testing.expectEqualSlices(u16, L("%cde%"), it.next().?);
        try std.testing.expectEqualSlices(u16, L("/f/"), it.next().?);
        try std.testing.expectEqualSlices(u16, L("%ghi%"), it.next().?);
        try std.testing.expect(it.next() == null);
    }
    {
        var it = UnexpandedIterator{ .buffer = L("%foo%") };
        try std.testing.expectEqualSlices(u16, L("%foo%"), it.next().?);
        try std.testing.expect(it.next() == null);
    }
    {
        var it = UnexpandedIterator{ .buffer = L("%foo") };
        try std.testing.expectEqualSlices(u16, L("%foo"), it.next().?);
        try std.testing.expect(it.next() == null);
    }
    {
        var it = UnexpandedIterator{ .buffer = L("%foo%/abc") };
        try std.testing.expectEqualSlices(u16, L("%foo%"), it.next().?);
        try std.testing.expectEqualSlices(u16, L("/abc"), it.next().?);
        try std.testing.expect(it.next() == null);
    }
}

fn expandPath(unexpanded: []const u16, registry: *LazyRegistry) GetPathError!windows.PathSpace {
    // Special case for certain environment variables that are expanded before
    // using actual environment variables.
    var buf = windows.PathSpace{ .data = undefined, .len = 0 };
    var it = UnexpandedIterator{ .buffer = unexpanded };
    while (it.next()) |part| {
        if (windows.eqlIgnoreCaseWTF16(part, L("%WINDIR%"))) {
            // TODO: This is probably able to be replaced by a read of PEB.ReadOnlyStaticServerData
            // https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/include/reactos/subsys/win/base.h#L109-L136
            const written_code_units = misc.windows.kernel32.GetWindowsDirectoryW(buf.data[buf.len..], @intCast((buf.data.len - buf.len) * 2));
            if (written_code_units == 0) switch (windows.kernel32.GetLastError()) {
                else => |err| return windows.unexpectedError(err),
            };
            buf.len += written_code_units;
        } else if (windows.eqlIgnoreCaseWTF16(part, L("%SystemDrive%"))) {
            // TODO: This is probably able to be replaced by a read of PEB.ReadOnlyStaticServerData
            // https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/include/reactos/subsys/win/base.h#L109-L136
            const written_code_units = misc.windows.kernel32.GetWindowsDirectoryW(buf.data[buf.len..], @intCast((buf.data.len - buf.len) * 2));
            if (written_code_units == 0) switch (windows.kernel32.GetLastError()) {
                else => |err| return windows.unexpectedError(err),
            };
            // The Windows directory must be on a drive with a drive letter, and we
            // only care about the drive letter and the colon.
            buf.len += 2;
        } else if (windows.eqlIgnoreCaseWTF16(part, L("%USERPROFILE%"))) {
            var token: windows.HANDLE = undefined;
            var rc = misc.windows.ntdll.NtOpenProcessToken(misc.windows.NtCurrentProcess, misc.windows.TOKEN_QUERY, &token);
            switch (rc) {
                .SUCCESS => {},
                else => return windows.unexpectedStatus(rc),
            }

            // This buffer is also used for the memory of the SID (that is, the `Sid` field
            // will point to a location within this buffer), so it needs to be large
            // enough for both the TOKEN_USER struct, the SID struct, and the
            // variable length SubAuthority of the SID.
            const max_sub_authorities_bytes = misc.windows.SID_MAX_SUB_AUTHORITIES * @sizeOf(windows.ULONG);
            var sid_buf: [@sizeOf(misc.windows.TOKEN_USER) + @sizeOf(misc.windows.SID) + max_sub_authorities_bytes]u8 align(@alignOf(misc.windows.TOKEN_USER)) = undefined;
            var info_length: windows.ULONG = undefined;
            rc = misc.windows.ntdll.NtQueryInformationToken(token, .TokenUser, &sid_buf, sid_buf.len, &info_length);
            switch (rc) {
                .SUCCESS => {},
                else => return windows.unexpectedStatus(rc),
            }
            const token_user: *misc.windows.TOKEN_USER = @ptrCast(&sid_buf);

            var str_buf: [sid_max_string_length:0]u16 = undefined;
            var unicode_string = windows.UNICODE_STRING{
                .Length = 0,
                .MaximumLength = str_buf.len * 2,
                .Buffer = &str_buf,
            };
            rc = misc.windows.ntdll.RtlConvertSidToUnicodeString(&unicode_string, token_user.User.Sid, @intFromBool(false));
            switch (rc) {
                .SUCCESS => {},
                else => unreachable,
            }

            const key_sub_path = str_buf[0 .. unicode_string.Length / 2 :0];
            const profile_list_key = registry.getHKLMProfileListKey() catch |err| switch (err) {
                error.FileNotFound => return error.PathNotFound,
                else => |e| return e,
            };
            var key: windows.HKEY = undefined;
            const open_result = std.os.windows.advapi32.RegOpenKeyExW(
                profile_list_key,
                key_sub_path,
                0,
                windows.KEY_QUERY_VALUE,
                &key,
            );
            switch (@as(windows.Win32Error, @enumFromInt(open_result))) {
                .SUCCESS => {},
                .FILE_NOT_FOUND => return error.PathNotFound,
                else => |err| return windows.unexpectedError(err),
            }

            const value = getRegistryStringValue(buf.data[buf.len..], key, L("ProfileImagePath")) catch |err| switch (err) {
                error.FileNotFound => return error.PathNotFound,
                error.BufferTooSmall => return error.PathTooLong,
                error.NotAString => return error.PathNotFound,
                error.Unexpected => |e| return e,
            };
            buf.len += value.len;
        } else if (windows.eqlIgnoreCaseWTF16(part, L("%ProgramData%"))) {
            const unused_slice = buf.data[buf.len..];
            const profile_list_key = registry.getHKLMProfileListKey() catch |err| switch (err) {
                error.FileNotFound => return error.PathNotFound,
                else => |e| return e,
            };
            const value = getRegistryStringValue(unused_slice, profile_list_key, KnownFolder.program_data.getMetadata().reg_name.?) catch |err| switch (err) {
                // Returning a 'not found' error when the value in CurrentVersion
                // is not found matches the behavior of SHGetKnownFolderPath.
                error.FileNotFound => return error.PathNotFound,
                error.BufferTooSmall => return error.PathTooLong,
                error.NotAString => return error.PathNotFound,
                error.Unexpected => |e| return e,
            };
            buf.len += value.len;
        } else if (windows.eqlIgnoreCaseWTF16(part, L("%PUBLIC%"))) {
            const unused_slice = buf.data[buf.len..];
            const profile_list_key = registry.getHKLMProfileListKey() catch |err| switch (err) {
                error.FileNotFound => return error.PathNotFound,
                else => |e| return e,
            };
            const value = getRegistryStringValue(unused_slice, profile_list_key, KnownFolder.public.getMetadata().reg_name.?) catch |err| switch (err) {
                // Returning a 'not found' error when the value in CurrentVersion
                // is not found matches the behavior of SHGetKnownFolderPath.
                error.FileNotFound => return error.PathNotFound,
                error.BufferTooSmall => return error.PathTooLong,
                error.NotAString => return error.PathNotFound,
                error.Unexpected => |e| return e,
            };
            buf.len += value.len;
        } else {
            @memcpy(buf.data[buf.len..][0..part.len], part);
            buf.len += part.len;
        }
    }

    // Resolve any remaining unexpanded environment variables (e.g. if a User Shell Folder
    // redirection has an uncommon environment variable within its path).
    if (std.mem.indexOfScalar(u16, buf.data[0..buf.len], '%') != null) {
        var rtl_buf: windows.PathSpace = undefined;

        var source_str = windows.UNICODE_STRING{
            .Length = @intCast(buf.len * 2),
            .MaximumLength = @intCast(buf.len * 2),
            .Buffer = &buf.data,
        };
        var dest_str = windows.UNICODE_STRING{
            .Length = 0,
            .MaximumLength = @intCast(rtl_buf.data.len * 2),
            .Buffer = &rtl_buf.data,
        };

        var returned_byte_length: windows.ULONG = undefined;
        const rc = misc.windows.ntdll.RtlExpandEnvironmentStrings_U(null, &source_str, &dest_str, &returned_byte_length);
        switch (rc) {
            .SUCCESS => {},
            .BUFFER_TOO_SMALL => return error.PathTooLong,
            else => return error.Unexpected,
        }
        const code_unit_len = returned_byte_length / 2 - 1;
        std.debug.assert(rtl_buf.data[code_unit_len] == 0);

        rtl_buf.len = code_unit_len;
        return rtl_buf;
    } else {
        buf.data[buf.len] = 0;
        return buf;
    }
}

test "get vs SHGetKnownFolderPath" {
    if (@import("builtin").target.os.tag != .windows) return error.SkipZigTest;

    // getPath matches the behavior of SHGetKnownFolderPath except in one particular scenario:
    // - We are looking up the path for the known folder `user_profiles`.
    // - The ProfilesDirectory registry value contains the %SystemDrive% environment variable.
    // - The %SystemDrive% environment variable is not set.
    // If all of the above are true, then SHGetKnownFolderPath will return a path with
    // an unexpanded %SystemDrive% within it, while `getPath` will return a path with
    // the %SystemDrive% expanded without relying on the environment variable.
    //
    // To avoid false negatives for this known difference, we check the environment to
    // see if we should skip checking `user_profiles`.
    const should_skip_user_profiles = std.os.getenvW(L("SystemDrive")) == null;

    const values = std.enums.values(KnownFolder);
    for (values) |folder| {
        var dir_path_ptr: [*:0]u16 = undefined;
        switch (SHGetKnownFolderPath(
            &folder.getMetadata().id,
            windows.KF_FLAG_DONT_VERIFY,
            null,
            &dir_path_ptr,
        )) {
            windows.S_OK => {},
            windows.E_OUTOFMEMORY => return error.OutOfMemory,
            else => |hresult| {
                const actual_path_space = getPath(folder) catch {
                    // Both failed
                    continue;
                };
                std.debug.print("SHGetKnownFolderPath errored with {} ({})\n", .{ hresult, windows.HRESULT_CODE(hresult) });
                std.debug.print("but getPath succeeded and returned: {}\n", .{std.unicode.fmtUtf16le(actual_path_space.span())});
                return error.UnexpectedSuccess;
            },
        }
        const expected_path = std.mem.span(dir_path_ptr);
        defer CoTaskMemFree(dir_path_ptr);

        const actual_path_space = try getPath(folder);

        std.testing.expectEqualSlices(u16, expected_path, actual_path_space.span()) catch |err| {
            if (folder == .user_profiles and should_skip_user_profiles) continue;
            std.debug.print("folder: {s}\n", .{@tagName(folder)});
            std.debug.print("expected: {}\n", .{std.unicode.fmtUtf16le(expected_path)});
            std.debug.print("actual: {}\n", .{std.unicode.fmtUtf16le(actual_path_space.span())});
            return err;
        };
    }
}

// Depending on shell32.dll incurs a performance penalty on program initialization.
// This binding is only intended to be used during tests.
extern "shell32" fn SHGetKnownFolderPath(
    rfid: *const windows.KNOWNFOLDERID,
    dwFlags: windows.DWORD,
    hToken: ?windows.HANDLE,
    ppszPath: *[*:0]windows.WCHAR,
) callconv(windows.WINAPI) windows.HRESULT;

// Depending on ole32.dll incurs a performance penalty on program initialization.
// This binding is only intended to be used during tests.
extern "ole32" fn CoTaskMemFree(pv: windows.LPVOID) callconv(windows.WINAPI) void;

/// The maximum number of characters that a SID string can occupy. Since SID strings
/// only contain ASCII code points, this represents the maximum length in both ASCII/UTF-8
/// bytes and UTF-16 code units.
///
/// https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components
///
/// S-R-I-S...
///
/// - S is the literal character 'S'
/// - R is the revision level, which is represented as base 10
/// - I is the identifier-authority value, which can be represented as a base 10 integer when
///   Value[0] and Value[1] are zero, in which case it can use a maximum of 9 digits
///   since the remaining 4 bytes are used to form a u32, or it can be representated
///   as 0x00112233445566 where 00 corresponds to Value[0] and 11 corresponds to Value[1], etc
///   in which case it will always use 16 characters
/// - S... is one or more subauthority values, where each are represented as base 10
///   integers that have a max of 9 digits (u32) and are separated by a `-`.
const sid_max_string_length: c_ushort = 1 + // S
    1 + // -
    std.math.log10_int(@as(u8, std.math.maxInt(u8))) + // R
    1 + // -
    2 + (@as(c_ushort, @as(misc.windows.SID_IDENTIFIER_AUTHORITY, undefined).Value.len * 2)) + // I
    1 + // -
    @as(c_ushort, std.math.log10_int(@as(u32, std.math.maxInt(u32)))) * misc.windows.SID_MAX_SUB_AUTHORITIES +
    (misc.windows.SID_MAX_SUB_AUTHORITIES - 1) // - between sub authorities
;

/// https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
pub const KnownFolder = enum {
    network_folder,
    computer_folder,
    internet_folder,
    control_panel_folder,
    printers_folder,
    sync_manager_folder,
    sync_setup_folder,
    conflict_folder,
    sync_results_folder,
    recycle_bin_folder,
    connections_folder,
    fonts,
    desktop,
    startup,
    programs,
    start_menu,
    recent,
    send_to,
    documents,
    favorites,
    net_hood,
    print_hood,
    templates,
    common_startup,
    common_programs,
    common_start_menu,
    public_desktop,
    program_data,
    common_templates,
    public_documents,
    roaming_app_data,
    local_app_data,
    local_app_data_low,
    internet_cache,
    cookies,
    history,
    system,
    system_x86,
    windows,
    profile,
    pictures,
    program_files_x86,
    program_files_common_x86,
    program_files_x64,
    program_files_common_x64,
    program_files,
    program_files_common,
    user_program_files,
    user_program_files_common,
    admin_tools,
    common_admin_tools,
    music,
    videos,
    ringtones,
    public_pictures,
    public_music,
    public_videos,
    public_ringtones,
    resource_dir,
    localized_resources_dir,
    common_oem_links,
    cd_burning,
    user_profiles,
    playlists,
    sample_playlists,
    sample_music,
    sample_pictures,
    sample_videos,
    photo_albums,
    public,
    change_remove_programs,
    app_updates,
    add_new_programs,
    downloads,
    public_downloads,
    saved_searches,
    quick_launch,
    contacts,
    sidebar_parts,
    sidebar_default_parts,
    public_game_tasks,
    game_tasks,
    saved_games,
    /// Deprecated
    games,
    search_mapi,
    search_csc,
    links,
    users_files,
    users_libraries,
    search_home,
    original_images,
    documents_library,
    music_library,
    pictures_library,
    videos_library,
    recorded_tv_library,
    home_group,
    home_group_current_user,
    device_metadata_store,
    libraries,
    public_libraries,
    user_pinned,
    implicit_app_shortcuts,
    account_pictures,
    public_user_tiles,
    apps_folder,
    start_menu_all_programs,
    common_start_menu_places,
    application_shortcuts,
    roaming_tiles,
    roamed_tile_images,
    screenshots,
    camera_roll,
    /// Deprecated, same as one_drive
    sky_drive,
    one_drive,
    sky_drive_documents,
    sky_drive_pictures,
    sky_drive_music,
    sky_drive_camera_roll,
    search_history,
    search_templates,
    camera_roll_library,
    saved_pictures,
    saved_pictures_library,
    retail_demo,
    device,
    development_files,
    objects_3d,
    app_captures,
    local_documents,
    local_pictures,
    local_videos,
    local_music,
    local_downloads,
    recorded_calls,
    all_app_mods,
    current_app_mods,
    app_data_desktop,
    app_data_documents,
    app_data_favorites,
    app_data_program_data,
    local_storage,

    pub fn getMetadata(known_folder: KnownFolder) Metadata {
        return known_folder_metadata[@intFromEnum(known_folder)];
    }

    pub const Category = enum(windows.DWORD) {
        /// No equivalent KF_ constant, this is specific to the Zig implementation
        not_found,
        /// Equal to KF_CATEGORY_VIRTUAL
        virtual,
        /// Equal to KF_CATEGORY_FIXED
        fixed,
        /// Equal to KF_CATEGORY_COMMON
        common,
        /// Equal to KF_CATEGORY_PERUSER
        peruser,
    };

    pub const Metadata = struct {
        id: GUID,
        category: Category = .peruser,
        /// Registry value name for folders that get looked up in
        /// `User Shell Folders` / `ProfileList` / `CurrentVersion`
        /// using something other than their GUID.
        reg_name: ?[:0]const u16 = null,
        parent: ?KnownFolder = null,
        default_path: ?[:0]const u16 = null,
    };
};

/// https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
/// Names and GUIDs come from KnownFolders.h of Windows SDK 10.0.22621.0
const known_folder_metadata = blk: {
    @setEvalBranchQuota(20000);
    break :blk std.enums.directEnumArray(KnownFolder, KnownFolder.Metadata, 0, .{
        .network_folder = .{
            .id = GUID.parse("{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}"),
            .category = .virtual,
        },
        .computer_folder = .{
            .id = GUID.parse("{0AC0837C-BBF8-452A-850D-79D08E667CA7}"),
            .category = .virtual,
        },
        .internet_folder = .{
            .id = GUID.parse("{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}"),
            .category = .virtual,
        },
        .control_panel_folder = .{
            .id = GUID.parse("{82A74AEB-AEB4-465C-A014-D097EE346D63}"),
            .category = .virtual,
        },
        .printers_folder = .{
            .id = GUID.parse("{76FC4E2D-D6AD-4519-A663-37BD56068185}"),
            .category = .virtual,
        },
        .sync_manager_folder = .{
            .id = GUID.parse("{43668BF8-C14E-49B2-97C9-747784D784B7}"),
            .category = .virtual,
        },
        .sync_setup_folder = .{
            .id = GUID.parse("{0F214138-B1D3-4a90-BBA9-27CBC0C5389A}"),
            .category = .virtual,
        },
        .conflict_folder = .{
            .id = GUID.parse("{4bfefb45-347d-4006-a5be-ac0cb0567192}"),
            .category = .virtual,
        },
        .sync_results_folder = .{
            .id = GUID.parse("{289a9a43-be44-4057-a41b-587a76d7e7f9}"),
            .category = .virtual,
        },
        .recycle_bin_folder = .{
            .id = GUID.parse("{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}"),
            .category = .virtual,
        },
        .connections_folder = .{
            .id = GUID.parse("{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}"),
            .category = .virtual,
        },
        .fonts = .{
            .id = GUID.parse("{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}"),
            .category = .fixed,
            .parent = .windows,
            .default_path = L("Fonts"),
        },
        .desktop = .{
            .id = GUID.parse("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"),
            .reg_name = L("Desktop"),
            .parent = .profile,
        },
        .startup = .{
            .id = GUID.parse("{B97D20BB-F46A-4C97-BA10-5E3608430854}"),
            .reg_name = L("StartUp"),
            .parent = .programs,
        },
        .programs = .{
            .id = GUID.parse("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}"),
            .reg_name = L("Programs"),
            .parent = .start_menu,
            .default_path = L("Programs"),
        },
        .start_menu = .{
            .id = GUID.parse("{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}"),
            .reg_name = L("Start Menu"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\Start Menu"),
        },
        .recent = .{
            .id = GUID.parse("{AE50C081-EBD2-438A-8655-8A092E34987A}"),
            .reg_name = L("Recent"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\Recent"),
        },
        .send_to = .{
            .id = GUID.parse("{8983036C-27C0-404B-8F08-102D10DCFD74}"),
            .reg_name = L("SendTo"),
        },
        .documents = .{
            .id = GUID.parse("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"),
            .reg_name = L("Personal"),
            .parent = .profile,
            .default_path = L("Documents"),
        },
        .favorites = .{
            .id = GUID.parse("{1777F761-68AD-4D8A-87BD-30B759FA33DD}"),
            .reg_name = L("Favorites"),
            .default_path = L("Favorites"),
        },
        .net_hood = .{
            .id = GUID.parse("{C5ABBF53-E17F-4121-8900-86626FC2C973}"),
            .reg_name = L("NetHood"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\Network Shortcuts"),
        },
        .print_hood = .{
            .id = GUID.parse("{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}"),
            .reg_name = L("PrintHood"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\Printer Shortcuts"),
        },
        .templates = .{
            .id = GUID.parse("{A63293E8-664E-48DB-A079-DF759E0509F7}"),
            .reg_name = L("Templates"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\Templates"),
        },
        .common_startup = .{
            .id = GUID.parse("{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}"),
            .reg_name = L("Common Startup"),
            .category = .common,
            .parent = .common_programs,
            .default_path = L("StartUp"),
        },
        .common_programs = .{
            .id = GUID.parse("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}"),
            .reg_name = L("Common Programs"),
            .category = .common,
            .parent = .common_start_menu,
            .default_path = L("Programs"),
        },
        .common_start_menu = .{
            .id = GUID.parse("{A4115719-D62E-491D-AA7C-E74B8BE3B067}"),
            .reg_name = L("Common Start Menu"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\Start Menu"),
        },
        .public_desktop = .{
            .id = GUID.parse("{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}"),
            .reg_name = L("Common Desktop"),
            .category = .common,
            .parent = .public,
            .default_path = L("Desktop"),
        },
        .program_data = .{
            .id = GUID.parse("{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"),
            .reg_name = L("ProgramData"),
            .category = .fixed,
        },
        .common_templates = .{
            .id = GUID.parse("{B94237E7-57AC-4347-9151-B08C6C32D1F7}"),
            .reg_name = L("Common Templates"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\Templates"),
        },
        .public_documents = .{
            .id = GUID.parse("{ED4824AF-DCE4-45A8-81E2-FC7965083634}"),
            .reg_name = L("Common Documents"),
            .category = .common,
            .parent = .public,
            .default_path = L("Documents"),
        },
        .roaming_app_data = .{
            .id = GUID.parse("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"),
            .reg_name = L("AppData"),
            .parent = .profile,
            .default_path = L("AppData\\Roaming"),
        },
        .local_app_data = .{
            .id = GUID.parse("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"),
            .reg_name = L("Local AppData"),
            .parent = .profile,
            .default_path = L("AppData\\Local"),
        },
        .local_app_data_low = .{
            .id = GUID.parse("{A520A1A4-1780-4FF6-BD18-167343C5AF16}"),
            .parent = .profile,
            .default_path = L("AppData\\LocalLow"),
        },
        .internet_cache = .{
            .id = GUID.parse("{352481E8-33BE-4251-BA85-6007CAEDCF9D}"),
            .reg_name = L("Cache"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\INetCache"),
        },
        .cookies = .{
            .id = GUID.parse("{2B0F765D-C0E9-4171-908E-08A611B84FF6}"),
            .reg_name = L("Cookies"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\INetCookies"),
        },
        .history = .{
            .id = GUID.parse("{D9DC8A3B-B784-432E-A781-5A1130A75963}"),
            .reg_name = L("History"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\History"),
        },
        .system = .{
            .id = GUID.parse("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"),
            .category = .fixed,
        },
        .system_x86 = .{
            .id = GUID.parse("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"),
            .category = .fixed,
        },
        .windows = .{
            .id = GUID.parse("{F38BF404-1D43-42F2-9305-67DE0B28FC23}"),
            .category = .fixed,
        },
        .profile = .{
            .id = GUID.parse("{5E6C858F-0E22-4760-9AFE-EA3317B67173}"),
            .category = .fixed,
        },
        .pictures = .{
            .id = GUID.parse("{33E28130-4E1E-4676-835A-98395C3BC3BB}"),
            .reg_name = L("My Pictures"),
            .parent = .profile,
            .default_path = L("Pictures"),
        },
        .program_files_x86 = .{
            .id = GUID.parse("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"),
            .reg_name = L("ProgramFilesDir (x86)"),
            .category = .fixed,
        },
        .program_files_common_x86 = .{
            .id = GUID.parse("{DE974D24-D9C6-4D3E-BF91-F4455120B917}"),
            .reg_name = L("CommonFilesDir (x86)"),
            .category = .fixed,
        },
        .program_files_x64 = .{
            .id = GUID.parse("{6D809377-6AF0-444b-8957-A3773F02200E}"),
            .reg_name = L("ProgramFilesDir"),
            .category = .fixed,
        },
        .program_files_common_x64 = .{
            .id = GUID.parse("{6365D5A7-0F0D-45e5-87F6-0DA56B6A4F7D}"),
            .reg_name = L("CommonFilesDir"),
            .category = .fixed,
        },
        .program_files = .{
            .id = GUID.parse("{905e63b6-c1bf-494e-b29c-65b732d3d21a}"),
            .reg_name = L("ProgramFilesDir"),
            .category = .fixed,
        },
        .program_files_common = .{
            .id = GUID.parse("{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}"),
            .reg_name = L("CommonFilesDir"),
            .category = .fixed,
        },
        .user_program_files = .{
            .id = GUID.parse("{5cd7aee2-2219-4a67-b85d-6c9ce15660cb}"),
            .parent = .local_app_data,
            .default_path = L("Programs"),
        },
        .user_program_files_common = .{
            .id = GUID.parse("{bcbd3057-ca5c-4622-b42d-bc56db0ae516}"),
            .parent = .user_program_files,
            .default_path = L("Common"),
        },
        .admin_tools = .{
            .id = GUID.parse("{724EF170-A42D-4FEF-9F26-B60E846FBA4F}"),
            .reg_name = L("Administrative Tools"),
            .parent = .programs,
            .default_path = L("Administrative Tools"),
        },
        .common_admin_tools = .{
            .id = GUID.parse("{D0384E7D-BAC3-4797-8F14-CBA229B392B5}"),
            .reg_name = L("Common Administrative Tools"),
            .category = .common,
            .parent = .common_programs,
            .default_path = L("Administrative Tools"),
        },
        .music = .{
            .id = GUID.parse("{4BD8D571-6D19-48D3-BE97-422220080E43}"),
            .reg_name = L("My Music"),
            .parent = .profile,
            .default_path = L("Music"),
        },
        .videos = .{
            .id = GUID.parse("{18989B1D-99B5-455B-841C-AB7C74E4DDFC}"),
            .reg_name = L("My Videos"),
            .parent = .profile,
            .default_path = L("Videos"),
        },
        .ringtones = .{
            .id = GUID.parse("{C870044B-F49E-4126-A9C3-B52A1FF411E8}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\Ringtones"),
        },
        .public_pictures = .{
            .id = GUID.parse("{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}"),
            .reg_name = L("CommonPictures"),
            .category = .common,
            .parent = .public,
            .default_path = L("Pictures"),
        },
        .public_music = .{
            .id = GUID.parse("{3214FAB5-9757-4298-BB61-92A9DEAA44FF}"),
            .reg_name = L("CommonMusic"),
            .category = .common,
            .parent = .public,
            .default_path = L("Music"),
        },
        .public_videos = .{
            .id = GUID.parse("{2400183A-6185-49FB-A2D8-4A392A602BA3}"),
            .reg_name = L("CommonVideo"),
            .category = .common,
            .parent = .public,
            .default_path = L("Videos"),
        },
        .public_ringtones = .{
            .id = GUID.parse("{E555AB60-153B-4D17-9F04-A5FE99FC15EC}"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\Ringtones"),
        },
        .resource_dir = .{
            .id = GUID.parse("{8AD10C31-2ADB-4296-A8F7-E4701232C972}"),
            .category = .fixed,
        },
        .localized_resources_dir = .{
            .id = GUID.parse("{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}"),
            .category = .fixed,
        },
        .common_oem_links = .{
            .id = GUID.parse("{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("OEM Links"),
        },
        .cd_burning = .{
            .id = GUID.parse("{9E52AB10-F80D-49DF-ACB8-4330F5687855}"),
            .reg_name = L("CD Burning"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\Burn\\Burn"),
        },
        .user_profiles = .{
            .id = GUID.parse("{0762D272-C50A-4BB0-A382-697DCD729B80}"),
            .reg_name = L("ProfilesDirectory"),
            .category = .fixed,
        },
        .playlists = .{
            .id = GUID.parse("{DE92C1C7-837F-4F69-A3BB-86E631204A23}"),
            .parent = .music,
            .default_path = L("Playlists"),
        },
        .sample_playlists = .{
            .id = GUID.parse("{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}"),
            // In theory this should be 'common,' but for whatever reason
            // this particular GUID always errors with FILE_NOT_FOUND
            // when passed to SHGetKnownFolderPath, even when its
            // circumstances are identical to `sample_music` (i.e.
            // if both sample_playlists and sample_music do not have
            // an entry for their GUID in the FolderDescriptions registry,
            // only sample_playlists returns FILE_NOT_FOUND).
            .category = .not_found,
            .parent = .public_music,
            .default_path = L("Sample Playlists"),
        },
        .sample_music = .{
            .id = GUID.parse("{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}"),
            .category = .common,
            .parent = .public_music,
            .default_path = L("Sample Music"),
        },
        .sample_pictures = .{
            .id = GUID.parse("{C4900540-2379-4C75-844B-64E6FAF8716B}"),
            .category = .common,
            .parent = .public_pictures,
            .default_path = L("Sample Pictures"),
        },
        .sample_videos = .{
            .id = GUID.parse("{859EAD94-2E85-48AD-A71A-0969CB56A6CD}"),
            .category = .common,
            .parent = .public_videos,
            .default_path = L("Sample Videos"),
        },
        .photo_albums = .{
            .id = GUID.parse("{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}"),
            .parent = .pictures,
            .default_path = L("Slide Shows"),
        },
        .public = .{
            .id = GUID.parse("{DFDF76A2-C82A-4D63-906A-5644AC457385}"),
            .category = .fixed,
            .reg_name = L("Public"),
        },
        .change_remove_programs = .{
            .id = GUID.parse("{df7266ac-9274-4867-8d55-3bd661de872d}"),
            .category = .virtual,
        },
        .app_updates = .{
            .id = GUID.parse("{a305ce99-f527-492b-8b1a-7e76fa98d6e4}"),
            .category = .virtual,
        },
        .add_new_programs = .{
            .id = GUID.parse("{de61d971-5ebc-4f02-a3a9-6c82895e5c04}"),
            .category = .virtual,
        },
        .downloads = .{
            .id = GUID.parse("{374DE290-123F-4565-9164-39C4925E467B}"),
            .parent = .profile,
            .default_path = L("Downloads"),
        },
        .public_downloads = .{
            .id = GUID.parse("{3D644C9B-1FB8-4f30-9B45-F670235F79C0}"),
            .category = .common,
            .parent = .public,
            .default_path = L("Downloads"),
        },
        .saved_searches = .{
            .id = GUID.parse("{7d1d3a04-debb-4115-95cf-2f29da2920da}"),
            .parent = .profile,
            .default_path = L("Searches"),
        },
        .quick_launch = .{
            .id = GUID.parse("{52a4f021-7b75-48a9-9f6b-4b87a210bc8f}"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Internet Explorer\\Quick Launch"),
        },
        .contacts = .{
            .id = GUID.parse("{56784854-C6CB-462b-8169-88E350ACB882}"),
            .parent = .profile,
            .default_path = L("Contacts"),
        },
        .sidebar_parts = .{
            .id = GUID.parse("{A75D362E-50FC-4fb7-AC2C-A8BEAA314493}"),
            // It's unknown why this is the case, but this GUID always
            // returns FILE_NOT_FOUND when passed to SHGetKnownFolderPath.
            // Its true category would otherwise be `peruser`.
            .category = .not_found,
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows Sidebar\\Gadgets"),
        },
        .sidebar_default_parts = .{
            .id = GUID.parse("{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}"),
            // It's unknown why this is the case, but this GUID always
            // returns FILE_NOT_FOUND when passed to SHGetKnownFolderPath.
            // Its true category would otherwise be `common`.
            .category = .not_found,
            .parent = .program_files,
            .default_path = L("Windows Sidebar\\Gadgets"),
        },
        .public_game_tasks = .{
            .id = GUID.parse("{DEBF2536-E1A8-4c59-B6A2-414586476AEA}"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\GameExplorer"),
        },
        .game_tasks = .{
            .id = GUID.parse("{054FAE61-4DD8-4787-80B6-090220C4B700}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\GameExplorer"),
        },
        .saved_games = .{
            .id = GUID.parse("{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}"),
            .parent = .profile,
            .default_path = L("Saved Games"),
        },
        .games = .{
            .id = GUID.parse("{CAC52C1A-B53D-4edc-92D7-6B2E8AC19434}"),
            .category = .virtual,
        },
        .search_mapi = .{
            .id = GUID.parse("{98ec0e18-2098-4d44-8644-66979315a281}"),
            .category = .virtual,
        },
        .search_csc = .{
            .id = GUID.parse("{ee32e446-31ca-4aba-814f-a5ebd2fd6d5e}"),
            .category = .virtual,
        },
        .links = .{
            .id = GUID.parse("{bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968}"),
            .parent = .profile,
            .default_path = L("Links"),
        },
        .users_files = .{
            .id = GUID.parse("{f3ce0f7c-4901-4acc-8648-d5d44b04ef8f}"),
            .category = .virtual,
        },
        .users_libraries = .{
            .id = GUID.parse("{A302545D-DEFF-464b-ABE8-61C8648D939B}"),
            .category = .virtual,
        },
        .search_home = .{
            .id = GUID.parse("{190337d1-b8ca-4121-a639-6d472d16972a}"),
            .category = .virtual,
        },
        .original_images = .{
            .id = GUID.parse("{2C36C0AA-5812-4b87-BFD0-4CD0DFB19B39}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows Photo Gallery\\Original Images"),
        },
        .documents_library = .{
            .id = GUID.parse("{7b0db17d-9cd2-4a93-9733-46cc89022e7c}"),
            .parent = .libraries,
            .default_path = L("Documents.library-ms"),
        },
        .music_library = .{
            .id = GUID.parse("{2112AB0A-C86A-4ffe-A368-0DE96E47012E}"),
            .parent = .libraries,
            .default_path = L("Music.library-ms"),
        },
        .pictures_library = .{
            .id = GUID.parse("{A990AE9F-A03B-4e80-94BC-9912D7504104}"),
            .parent = .libraries,
            .default_path = L("Pictures.library-ms"),
        },
        .videos_library = .{
            .id = GUID.parse("{491E922F-5643-4af4-A7EB-4E7A138D8174}"),
            .parent = .libraries,
            .default_path = L("Videos.library-ms"),
        },
        .recorded_tv_library = .{
            .id = GUID.parse("{1A6FDBA2-F42D-4358-A798-B74D745926C5}"),
            .category = .common,
            .parent = .public_libraries,
            .default_path = L("RecordedTV.library-ms"),
        },
        .home_group = .{
            .id = GUID.parse("{52528A6B-B9E3-4add-B60D-588C2DBA842D}"),
            .category = .virtual,
        },
        .home_group_current_user = .{
            .id = GUID.parse("{9B74B6A3-0DFD-4f11-9E78-5F7800F2E772}"),
            .category = .virtual,
        },
        .device_metadata_store = .{
            .id = GUID.parse("{5CE4A5E9-E4EB-479D-B89F-130C02886155}"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\DeviceMetadataStore"),
        },
        .libraries = .{
            .id = GUID.parse("{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\Libraries"),
        },
        .public_libraries = .{
            .id = GUID.parse("{48daf80b-e6cf-4f4e-b800-0e69d84ee384}"),
            .category = .common,
            .parent = .public,
            .default_path = L("Libraries"),
        },
        .user_pinned = .{
            .id = GUID.parse("{9e3995ab-1f9c-4f13-b827-48b24b6c7174}"),
            .parent = .quick_launch,
            .default_path = L("User Pinned"),
        },
        .implicit_app_shortcuts = .{
            .id = GUID.parse("{bcb5256f-79f6-4cee-b725-dc34e402fd46}"),
            .parent = .user_pinned,
            .default_path = L("ImplicitAppShortcuts"),
        },
        .account_pictures = .{
            .id = GUID.parse("{008ca0b1-55b4-4c56-b8a8-4de4b299d3be}"),
            .parent = .roaming_app_data,
            .default_path = L("Microsoft\\Windows\\AccountPictures"),
        },
        .public_user_tiles = .{
            .id = GUID.parse("{0482af6c-08f1-4c34-8c90-e17ec98b1e17}"),
            .category = .common,
            .parent = .public,
            .default_path = L("AccountPictures"),
        },
        .apps_folder = .{
            .id = GUID.parse("{1e87508d-89c2-42f0-8a7e-645a0f50ca58}"),
            .category = .virtual,
        },
        .start_menu_all_programs = .{
            .id = GUID.parse("{F26305EF-6948-40B9-B255-81453D09C785}"),
            // Completely undocumented and SHGetKnownFolderPath returns
            // FILE_NOT_FOUND.
            .category = .not_found,
        },
        .common_start_menu_places = .{
            .id = GUID.parse("{A440879F-87A0-4F7D-B700-0207B966194A}"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\Start Menu Places"),
        },
        .application_shortcuts = .{
            .id = GUID.parse("{A3918781-E5F2-4890-B3D9-A7E54332328C}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\Application Shortcuts"),
        },
        .roaming_tiles = .{
            .id = GUID.parse("{00BCFC5A-ED94-4e48-96A1-3F6217F21990}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\RoamingTiles"),
        },
        .roamed_tile_images = .{
            .id = GUID.parse("{AAA8D5A5-F1D6-4259-BAA8-78E7EF60835E}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\RoamedTileImages"),
        },
        .screenshots = .{
            .id = GUID.parse("{b7bede81-df94-4682-a7d8-57a52620b86f}"),
            .parent = .pictures,
            .default_path = L("Screenshots"),
        },
        .camera_roll = .{
            .id = GUID.parse("{AB5FB87B-7CE2-4F83-915D-550846C9537B}"),
            .parent = .pictures,
            .default_path = L("Camera Roll"),
        },
        .sky_drive = .{
            .id = GUID.parse("{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}"),
            .parent = .profile,
            .default_path = L("OneDrive"),
        },
        .one_drive = .{
            .id = GUID.parse("{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}"),
            .parent = .profile,
            .default_path = L("OneDrive"),
        },
        .sky_drive_documents = .{
            .id = GUID.parse("{24D89E24-2F19-4534-9DDE-6A6671FBB8FE}"),
            .parent = .one_drive,
            .default_path = L("Documents"),
        },
        .sky_drive_pictures = .{
            .id = GUID.parse("{339719B5-8C47-4894-94C2-D8F77ADD44A6}"),
            .parent = .one_drive,
            .default_path = L("Pictures"),
        },
        .sky_drive_music = .{
            .id = GUID.parse("{C3F2459E-80D6-45DC-BFEF-1F769F2BE730}"),
            .parent = .one_drive,
            .default_path = L("Music"),
        },
        .sky_drive_camera_roll = .{
            .id = GUID.parse("{767E6811-49CB-4273-87C2-20F355E1085B}"),
            .parent = .sky_drive_pictures,
            .default_path = L("Camera Roll"),
        },
        .search_history = .{
            .id = GUID.parse("{0D4C3DB6-03A3-462F-A0E6-08924C41B5D4}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\ConnectedSearch\\History"),
        },
        .search_templates = .{
            .id = GUID.parse("{7E636BFE-DFA9-4D5E-B456-D7B39851D8A9}"),
            .parent = .local_app_data,
            .default_path = L("Microsoft\\Windows\\ConnectedSearch\\Templates"),
        },
        .camera_roll_library = .{
            .id = GUID.parse("{2B20DF75-1EDA-4039-8097-38798227D5B7}"),
            .parent = .libraries,
            .default_path = L("CameraRoll.library-ms"),
        },
        .saved_pictures = .{
            .id = GUID.parse("{3B193882-D3AD-4eab-965A-69829D1FB59F}"),
            .parent = .pictures,
            .default_path = L("Saved Pictures"),
        },
        .saved_pictures_library = .{
            .id = GUID.parse("{E25B5812-BE88-4bd9-94B0-29233477B6C3}"),
            .parent = .libraries,
            .default_path = L("SavedPictures.library-ms"),
        },
        .retail_demo = .{
            .id = GUID.parse("{12D4C69E-24AD-4923-BE19-31321C43A767}"),
            .category = .common,
            .parent = .program_data,
            .default_path = L("Microsoft\\Windows\\RetailDemo"),
        },
        .device = .{
            .id = GUID.parse("{1C2AC1DC-4358-4B6C-9733-AF21156576F0}"),
            .category = .virtual,
        },
        .development_files = .{
            .id = GUID.parse("{DBE8E08E-3053-4BBC-B183-2A7B2B191E59}"),
            .parent = .local_app_data,
            .default_path = L("DevelopmentFiles"),
        },
        .objects_3d = .{
            .id = GUID.parse("{31C0DD25-9439-4F12-BF41-7FF4EDA38722}"),
            .parent = .profile,
            .default_path = L("3D Objects"),
        },
        .app_captures = .{
            .id = GUID.parse("{EDC0FE71-98D8-4F4A-B920-C8DC133CB165}"),
            .parent = .videos,
            .default_path = L("Captures"),
        },
        .local_documents = .{
            .id = GUID.parse("{f42ee2d3-909f-4907-8871-4c22fc0bf756}"),
            .parent = .profile,
            .default_path = L("Documents"),
        },
        .local_pictures = .{
            .id = GUID.parse("{0ddd015d-b06c-45d5-8c4c-f59713854639}"),
            .parent = .profile,
            .default_path = L("Pictures"),
        },
        .local_videos = .{
            .id = GUID.parse("{35286a68-3c57-41a1-bbb1-0eae73d76c95}"),
            .parent = .profile,
            .default_path = L("Videos"),
        },
        .local_music = .{
            .id = GUID.parse("{a0c69a99-21c8-4671-8703-7934162fcf1d}"),
            .parent = .profile,
            .default_path = L("Music"),
        },
        .local_downloads = .{
            .id = GUID.parse("{7d83ee9b-2244-4e70-b1f5-5393042af1e4}"),
            .parent = .profile,
            .default_path = L("Downloads"),
        },
        .recorded_calls = .{
            .id = GUID.parse("{2f8b40c2-83ed-48ee-b383-a1f157ec6f9a}"),
            .parent = .profile,
            .default_path = L("Recorded Calls"),
        },
        .all_app_mods = .{
            .id = GUID.parse("{7ad67899-66af-43ba-9156-6aad42e6c596}"),
            .parent = .profile,
            .default_path = L("AppMods"),
        },
        .current_app_mods = .{
            .id = GUID.parse("{3db40b20-2a30-4dbe-917e-771dd21dd099}"),
            // Completely undocumented and SHGetKnownFolderPath returns
            // FILE_NOT_FOUND.
            .category = .not_found,
        },
        .app_data_desktop = .{
            .id = GUID.parse("{B2C5E279-7ADD-439F-B28C-C41FE1BBF672}"),
            .parent = .local_app_data,
            .default_path = L("Desktop"),
        },
        .app_data_documents = .{
            .id = GUID.parse("{7BE16610-1F7F-44AC-BFF0-83E15F2FFCA1}"),
            .parent = .local_app_data,
            .default_path = L("Documents"),
        },
        .app_data_favorites = .{
            .id = GUID.parse("{7CFBEFBC-DE1F-45AA-B843-A542AC536CC9}"),
            .parent = .local_app_data,
            .default_path = L("Favorites"),
        },
        .app_data_program_data = .{
            .id = GUID.parse("{559D40A3-A036-40FA-AF61-84CB430A4D34}"),
            .parent = .local_app_data,
            .default_path = L("ProgramData"),
        },
        .local_storage = .{
            .id = GUID.parse("{B3EB08D3-A1F3-496B-865A-42B536CDA0EC}"),
            // Completely undocumented and SHGetKnownFolderPath returns
            // FILE_NOT_FOUND.
            .category = .not_found,
        },
    });
};
