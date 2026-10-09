# Preserving symbolic links

Linux and macOS clients can opt in to preserving symbolic links instead of
uploading the files or directories they point to:

```sh
seaf-cli config -k preserve_symlinks -v true
seaf-cli config -k ignore_symlinks -v false
seaf-cli stop
seaf-cli start
```

This is a client-wide setting and requires a daemon restart. It defaults to
false. `ignore_symlinks` still skips outgoing links if enabled. Windows clients
keep the regular-file representation described below.

Applets with preservation support expose **Preserve symbolic links** in
Settings. Selecting it clears **Don't sync symbolic links**, and selecting
that option clears preservation. Changing preservation requires restarting
both the applet and daemon. If restart is deferred, the daemon keeps its
previous link behavior until restart. The applet sources are maintained in
the separate `seafile-client` repository.

Enable preservation before downloading a library into an empty directory.
Already-downloaded regular placeholders are not converted by an unchanged-file
scan; download a fresh working copy to materialize those links. Changing the
setting does not retrospectively turn previously uploaded target contents into
links. Keep a backup when migrating an existing library that followed links.

## Behavior and compatibility

With preservation enabled, clients preserve the target exactly: relative paths, absolute paths,
dangling links, directory links, loops, and non-UTF-8 target bytes are supported.
Targets are not traversed. Paths are not rebased between machines. A target
that does not exist on another machine remains a dangling link.

On the server and older clients, each link is an ordinary non-executable
file at the same path, containing a small versioned record. Usernames and
Seafile's metadata format are unchanged. Ordinary scans, index reloads,
reindexing, and directory reconstruction preserve that representation. File
encryption uses the existing block-encryption path.

This compatibility applies to clients using **separate working directories**.
Do not run an older client on a working directory containing materialized
links, or disable preservation on that directory: such a client follows links
using its existing behavior. User edits or deletions of placeholders on an
older client are ordinary synchronized edits or deletions. An edited file
that is no longer a valid record becomes a regular file on clients with preservation enabled.

## Record format (version 1)

The bytes are:

1. A single NUL byte (`00`).
2. ASCII `SEAFILE-SYMLINK:8e5fd83c-3179-4e82-96d5-cc491901bea7:1:`.
3. Canonical, padded RFC 4648 base64 of the link target's filesystem bytes.

There is no trailing NUL or newline. Targets must contain between 1 and 4095
bytes and cannot contain NUL. Invalid encodings, unknown signatures/versions,
and oversized records remain regular files. A recognized record that cannot be
materialized causes a checkout error; it is not silently converted into a
regular file.

The NUL prefix and lack of newlines also keep a placeholder named
`seafile-ignore.txt` from introducing ignore patterns on older clients.

This signature is a reserved content format, not authentication. A regular file
whose complete contents match a valid record is interpreted as a link when
downloaded by a client with preservation enabled. Store such literal records in
an archive or use a client with preservation disabled if that interpretation is
unwanted.

Unchanged regular files do not need content inspection on each scan. Downloads
are inspected only if their size can fit a record; recognition reads at most
the bounded record size. Only actual local symlinks require record generation.

## Tests

On Linux, after configuring and building, run `make -C daemon check`.
The offline integration tests exercise the production chunker, encrypted block
storage, checkout, local index reloads, directory serialization, conflict
handling, and ordinary-file compatibility path. They do not require a server.
