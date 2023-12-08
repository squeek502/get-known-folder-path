get-known-folder-path
=====================

This is a repository focusing on implementing a function that is intended to be similar to [`SHGetKnownFolderPath`](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath) to get the same functionality in Zig while [avoiding the dependency on shell32.dll](https://randomascii.wordpress.com/2018/12/03/a-not-called-function-can-cause-a-5x-slowdown/). Ultimately, the intention is to merge the code in this repository into the Zig standard library in order to close https://github.com/ziglang/zig/issues/18098.

Two current features of the implementation that ideally will be maintained in the finished version:

- No heap allocation
- No recursion

This is a fully clean-room reimplementation with no decompilation involved. The method of reimplementation was/is the following:

- Used the [Wine implementation](https://gitlab.winehq.org/wine/wine/-/blob/master/dlls/shell32/shellpath.c#L3514) to get a general sense of how things might work, and used it for much of the metadata for each folder
- Wrote a program that calls `SHGetKnownFolderPath` for a given known folder and then ran it with [NtTrace](https://github.com/rogerorr/NtTrace) to see which registry keys, etc were accessed by `SHGetKnownFolderPath`. This was the main tool used to determine what a reimplementation should be doing.
- Checked that the Zig implementation matches `SHGetKnownFolderPath` outputs for all known folders (and additionally that the outputs match when no environment variables are set)

This is my current understanding about what `SHGetKnownFolderPath` is doing (this glosses over a lot of details, see the source code for a better understanding):

- If the folder is of category `virtual`, then `EFAIL` is returned by `SHGetKnownFolderPath`
- If the folder is one of `sample_playlists`, `sidebar_parts`, `sidebar_default_parts`, `start_menu_all_programs`, `current_app_mods`, or `local_storage` then `FILE_NOT_FOUND` is (always?) returned by `SHGetKnownFolderPath`. It is unclear exactly why this is the case.
- Lookup the GUID of the folder in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions`, e.g. for `local_app_data` that'd be the subkey `{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}` of `FolderDescriptions`. It's unclear what information it actually uses from this registry key (see known differences below).
- If the folder is of category `peruser` or `common`, then `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` is checked to see if the path has been redirected.
  + The root key is either `HKEY_CURRENT_USER` for `peruser` paths, or `HKEY_LOCAL_MACHINE` for `common` paths.
  + The name of the value in `User Shell Folders` may be a name (e.g. `Local AppData`) or it may be the GUID of the folder (e.g. `{374DE290-123F-4565-9164-39C4925E467B}`). Each folder will use one or the other, and which folder uses which seems to be completely arbitrary.
  + Other categories of path cannot be redirected and `User Shell Folders` is not checked for them.
  + If the path does not have an entry in `User Shell Folders`, the parent path will be looked up in `User Shell Folders` until it hits a `fixed` path
- If there is no redirected path in `User Shell Folders` or the path is of type `fixed`, then a path is constructed using various methods.
- Environment variables within the path are expanded, with special casing for certain environment variables that are resolved without actually accessing environment variables (e.g. `%WINDIR%`, `%SystemDrive%`, `%USERPROFILE%`, `%ProgramData%`, `%PUBLIC%`). When exactly this special casing takes place is not fully figured out yet (see known differences around `user_profiles` below).

## Status

With a default Windows 10 installation, here's how the Zig version currently compares to `SHGetKnownFolderPath` (with `KF_FLAG_DONT_VERIFY` set):

- With the default set of environment variables: for every known folder, the path returned is exactly the same 
- With no environment variables set at all: for every known folder except `user_profiles`, the path returned is exactly the same

Current known differences to SHGetKnownFolderPath:

- The Zig version does not support any KF_FLAG_ options (e.g. `KF_FLAG_CREATE`, etc) and instead always functions as if SHGetKnownFolderPath was called with the sole option KF_FLAG_DONT_VERIFY. That is, the Zig version does not verify that the path returns exists on the filesystem (while SHGetKnownFolderPath does that verification by default).
  + Support for most KF_ flags would complicate the implementation to a huge degree, since with e.g. the `CREATE` and `INIT` flags, SHGetKnownFolderPath can be responsible for things like creating/initializing special Library folders, desktop.ini files, folder attributes, etc, etc.
  + There's currently no plan to reimplement anything beyond getting a path.
- The Zig version does not support custom known folder GUIDs, and instead only allows retrieving the path for the default known folders in `KnownFolders.h`.
  + Example of how a custom known folder can be registered: https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/winui/shell/appplatform/knownfolders/kfdef.reg
  + Custom known folder GUIDs would need a slightly differently implementation, since it would need to look in the FolderDescriptions registry which the Zig version currently does not do (see below).
- The Zig version handles the `user_profiles` path differently:
  + SHGetKnownFolderPath will return a path without special-cased environment variables expanded (e.g. `%SystemDrive%`) if the environment variable is not set and `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory` contains that environment variable.
  + The Zig version instead will expand special case environment variables like `%SystemDrive%` for `user_profiles` without the need for the environment variable being set.
- The Zig version does not lookup the GUID in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions` at all. This is something that `SHGetKnownFolderPath` does for each known folder, but it doesn't seem to care that much about the values, or it only cares about the values for certain folders, or something. I couldn't make sense of when it matters (e.g. if the GUID for `local_app_data` is not in FolderDescriptions, SHGetKnownFolderPath still returns a path, but if the GUID for `local_app_data_low` is not in FolderDescriptions, then SHGetKnownFolderPath returns `FILE_NOT_FOUND`).
  + This needs to be investigated more. A list of every path that returns `FILE_NOT_FOUND` if its GUID does not have an entry in `FolderDescriptions` can be found here: https://gist.github.com/squeek502/b51adfa7490101baafecdecb4cf771b7

Potential next steps to improve conformance of the reimplementation:

- Modify [NtTrace](https://github.com/rogerorr/NtTrace) to include functions like `RtlQueryEnvironmentVariable`/`RtlQueryEnvironmentVariable_U`/`RtlExpandEnvironmentStrings_U` to get a more complete picture of how `SHGetKnownFolderPath` is functioning
- Write test programs that exercise more of the relevant variation in functionality that may not be accounted for, things like `FolderDescriptions` being missing/modified

## Compiling / testing

```
zig build
```

will give you a `zig-out/bin/knownfolder.exe`. When run without arguments, it will get the path of every known folder and print out any paths that returned an error or that have unexpanded environment variables. When run with an argument, it will look up the path of the specified known folder and print the result (the argument must be a field name of the `KnownFolder` enum).

```
zig build test
```

will run a test that compares the return of the Zig implementation with the return of `SHGetKnownFolderPath` (the target must be Windows for this test to run)

```
zig build tools
```

will build two programs:

- `zig-out/bin/shknownfolder.exe` which works the same as `knownfolder.exe` above, but will call `SHGetKnownFolderPath` to get the path of each known folder
- `zig-out/bin/spawnempty.exe` which will spawn a child process with a completely empty environment (no environment variables set at all) using the arguments you pass to it, e.g. `spawnempty.exe shknownfolder.exe program_data` which will print the unexpanded path `%SystemDrive%\ProgramData` with a default Windows 10 installation.
