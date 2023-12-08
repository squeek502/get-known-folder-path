//! Misc things that will be moved into the standard library once this is complete

const std = @import("std");
const builtin = @import("builtin");

pub const windows = struct {
    const HKEY = std.os.windows.HKEY;
    const USHORT = std.os.windows.USHORT;
    const ULONG = std.os.windows.ULONG;
    const HANDLE = std.os.windows.HANDLE;
    const BYTE = std.os.windows.BYTE;
    const UCHAR = std.os.windows.UCHAR;
    const WINAPI = std.os.windows.WINAPI;
    const LPWSTR = std.os.windows.LPWSTR;
    const UINT = std.os.windows.UINT;
    const LANGID = std.os.windows.LANGID;
    const ACCESS_MASK = std.os.windows.ACCESS_MASK;
    const NTSTATUS = std.os.windows.NTSTATUS;
    const BOOLEAN = std.os.windows.BOOLEAN;
    const UNICODE_STRING = std.os.windows.UNICODE_STRING;
    const PVOID = std.os.windows.PVOID;

    pub const ntdll = struct {
        pub extern "ntdll" fn NtOpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: ACCESS_MASK,
            TokenHandle: *HANDLE,
        ) callconv(WINAPI) NTSTATUS;

        pub extern "ntdll" fn NtQueryInformationToken(
            TokenHandle: HANDLE,
            TokenInformationClass: TOKEN_INFORMATION_CLASS,
            TokenInformation: *anyopaque,
            TokenInformationLength: ULONG,
            ReturnLength: *ULONG,
        ) callconv(WINAPI) NTSTATUS;

        pub extern "ntdll" fn RtlConvertSidToUnicodeString(
            UnicodeString: *UNICODE_STRING,
            Sid: *SID,
            AllocateDestinationString: BOOLEAN,
        ) callconv(WINAPI) NTSTATUS;

        pub extern "ntdll" fn RtlExpandEnvironmentStrings_U(
            Environment: ?PVOID,
            Source: *UNICODE_STRING,
            Destination: *UNICODE_STRING,
            ReturnedLength: *ULONG,
        ) callconv(WINAPI) NTSTATUS;
    };

    pub const kernel32 = struct {
        pub extern "kernel32" fn GetWindowsDirectoryW(lpBuffer: LPWSTR, uSize: UINT) callconv(WINAPI) UINT;
        pub extern "kernel32" fn GetSystemDirectoryW(lpBuffer: LPWSTR, uSize: UINT) callconv(WINAPI) UINT;
        pub extern "kernel32" fn GetSystemWow64DirectoryW(lpBuffer: LPWSTR, uSize: UINT) callconv(WINAPI) UINT;
        pub extern "kernel32" fn GetUserDefaultLangID() callconv(WINAPI) LANGID;
    };

    // This is a hack. Instead of this hacky workaround, `SystemProcessorInformation = 1,`
    // should just be added to the SYSTEM_INFORMATION_CLASS enum.
    pub fn SystemProcessorInformationEnum() std.os.windows.SYSTEM_INFORMATION_CLASS {
        const val: c_int = 1;
        return @as(*std.os.windows.SYSTEM_INFORMATION_CLASS, @ptrFromInt(@intFromPtr(&val))).*;
    }

    pub const HKEY_CURRENT_USER: HKEY = @ptrFromInt(0x80000001);
    pub const HKEY_USERS: HKEY = @ptrFromInt(0x80000003);

    pub const GUID = struct {
        // copied from std/os/windows.zig
        const hex_offsets = switch (builtin.target.cpu.arch.endian()) {
            .big => [16]u6{
                0,  2,  4,  6,
                9,  11, 14, 16,
                19, 21, 24, 26,
                28, 30, 32, 34,
            },
            .little => [16]u6{
                6,  4,  2,  0,
                11, 9,  16, 14,
                19, 21, 24, 26,
                28, 30, 32, 34,
            },
        };

        /// Length of a stringified GUID in characters, including the { and }
        pub const string_len = 38;

        pub fn stringify(self: std.os.windows.GUID) [string_len:0]u8 {
            return stringifyImpl(self, u8);
        }

        /// Returns UTF-16 LE
        pub fn stringifyW(self: std.os.windows.GUID) [string_len:0]u16 {
            return stringifyImpl(self, u16);
        }

        /// If T is u16, returns UTF-16 LE
        fn stringifyImpl(self: std.os.windows.GUID, comptime T: type) [string_len:0]T {
            var str: [string_len:0]T = comptime init: {
                var arr: [string_len:0]T = undefined;
                const bytes = "{00000000-0000-0000-0000-000000000000}".*;
                for (bytes, 0..) |byte, i| {
                    arr[i] = byte;
                }
                break :init arr;
            };
            const bytes: [16]u8 = @bitCast(self);
            for (hex_offsets, 0..) |hex_offset, i| {
                const str_index = hex_offset + 1;
                const byte = bytes[i];
                str[str_index] = std.mem.nativeToLittle(T, std.fmt.digitToChar(byte / 16, .upper));
                str[str_index + 1] = std.mem.nativeToLittle(T, std.fmt.digitToChar(byte % 16, .upper));
            }
            return str;
        }
    };

    pub const SYSTEM_PROCESSOR_INFORMATION = extern struct {
        ProcessorArchitecture: USHORT,
        ProcessorLevel: USHORT,
        ProcessorRevision: USHORT,
        MaximumProcessors: USHORT,
        ProcessorFeatureBits: ULONG,
    };

    /// x64 (AMD or Intel)
    pub const PROCESSOR_ARCHITECTURE_AMD64 = 9;
    /// ARM
    pub const PROCESSOR_ARCHITECTURE_ARM = 5;
    /// ARM64
    pub const PROCESSOR_ARCHITECTURE_ARM64 = 12;
    /// Intel Itanium-based
    pub const PROCESSOR_ARCHITECTURE_IA64 = 6;
    /// x86
    pub const PROCESSOR_ARCHITECTURE_INTEL = 0;
    pub const PROCESSOR_ARCHITECTURE_UNKNOWN = 0xffff;

    pub const TOKEN_INFORMATION_CLASS = enum(c_int) {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        MaxTokenInfoClass,
    };

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_sid_identifier_authority
    pub const SID_IDENTIFIER_AUTHORITY = extern struct {
        Value: [6]BYTE,
    };

    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_sid
    pub const SID = extern struct {
        Revision: UCHAR,
        SubAuthorityCount: UCHAR,
        IdentifierAuthority: SID_IDENTIFIER_AUTHORITY,
        /// Flexible array of length SubAuthorityCount
        SubAuthority: [1]ULONG,

        pub fn subAuthority(self: *const SID) []const ULONG {
            return @as([*]const ULONG, @ptrCast(&self.SubAuthority))[0..self.SubAuthorityCount];
        }
    };

    /// SID_MAX_SUB_AUTHORITIES is defined in WinNT.h as 15.
    pub const SID_MAX_SUB_AUTHORITIES = 15;

    pub const SID_AND_ATTRIBUTES = extern struct {
        Sid: *SID,
        Attributes: ULONG,
    };

    // Defined as a macro in wdm.h that returns `(HANDLE)(LONG_PTR) -1`
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/zwcurrentprocess
    pub const NtCurrentProcess: HANDLE = @ptrFromInt(std.math.maxInt(usize));

    // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
    pub const TOKEN_ASSIGN_PRIMARY = 0x0001;
    pub const TOKEN_DUPLICATE = 0x0002;
    pub const TOKEN_IMPERSONATE = 0x0004;
    pub const TOKEN_QUERY = 0x0008;
    pub const TOKEN_QUERY_SOURCE = 0x0010;
    pub const TOKEN_ADJUST_PRIVILEGES = 0x0020;
    pub const TOKEN_ADJUST_GROUPS = 0x0040;
    pub const TOKEN_ADJUST_DEFAULT = 0x0080;
    pub const TOKEN_ADJUST_SESSIONID = 0x0100;

    pub const TOKEN_USER = extern struct {
        User: SID_AND_ATTRIBUTES,
    };
};

test "GUID" {
    const guid = std.os.windows.GUID{
        .Data1 = 0x01234567,
        .Data2 = 0x89ab,
        .Data3 = 0xef10,
        .Data4 = "\x32\x54\x76\x98\xba\xdc\xfe\x91".*,
    };
    const str = windows.GUID.stringify(guid);
    try std.testing.expectEqualStrings("{01234567-89AB-EF10-3254-7698BADCFE91}", &str);
    const str_w = windows.GUID.stringifyW(guid);
    try std.testing.expectEqualSlices(
        u16,
        unicode.asciiToUtf16LeStringLiteral("{01234567-89AB-EF10-3254-7698BADCFE91}"),
        &str_w,
    );
}

pub const unicode = struct {
    /// Converts an ASCII string literal into a UTF-16LE string literal.
    pub fn asciiToUtf16LeStringLiteral(comptime ascii: []const u8) *const [ascii.len:0]u16 {
        return comptime blk: {
            var utf16le: [ascii.len:0]u16 = undefined;
            for (ascii, 0..) |c, i| {
                std.debug.assert(std.ascii.isASCII(c));
                utf16le[i] = std.mem.nativeToLittle(u16, c);
            }
            break :blk &utf16le;
        };
    }
};
