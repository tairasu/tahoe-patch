# tahoe-patch

Fixes freezing for 32-bit windows games on macOS Tahoe. Use apply/revert to flip the PE `NX_COMPAT` bit.

## Build

```bash
bash build.sh release
```

Output binary:

- `bin/tahoe-patch`

## Usage

Apply patch (sets `NX_COMPAT` bit `0x0100`):

```bash
./tahoe-patch apply "/path/to/file.dll"
```

Revert patch:

```bash
./tahoe-patch revert "/path/to/file.dll"
```

Revert with explicit backup:

```bash
./tahoe-patch revert "/path/to/file.dll" --backup "/path/to/backup.bak"
```

## Backups / Metadata

- On `apply`, a backup is created in `.<target-dir>/.tahoe-patch/`.
- Metadata is written to `<target>.tahoe.meta` and includes backup path + old/new header values.
- On `revert`, tool tries explicit `--backup`, then metadata backup, then fallback: clear NX bit in place.

## Obfuscation Notes

- Release build uses `-O3`, `-flto`, hidden symbol visibility, dead-strip, and symbol stripping.
- This hardens casual reverse inspection but is not a cryptographic protection boundary.
