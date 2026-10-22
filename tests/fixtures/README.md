# Test fixtures

These files exist only for abv0's own tests. They are not packages and are never published in the registry.

- `malware_sample.sh` is a detection test sample for the threat scanner. Do not run it.
- `7z/*.7z` are small archives made with 7-Zip 23.01 for `src/sevenzip.zig`. Most hold the same tree: `hello.txt`, `empty.txt`, `emptydir/`, `sub/dir/data.txt` (34488 bytes), `bin/prog.exe` (30002 bytes of x86-like code with many E8/E9 calls), a non-ASCII file name, and a symlink `link.txt`. The name says the method: `lzma2`, `lzma`, `copy`, `bcj_lzma` and `bcj_lzma2` (x86 filter), `nonsolid`, `plainhdr` (header not compressed), `smalldict_*` (4 KiB window, so the window wraps) and `lzma2_mixed` (stored and compressed LZMA2 chunks). `ppmd`, `bzip2`, `deflate`, `bcj2`, `enc_data` and `enc_hdr` (AES) exist to check that unsupported methods are refused.
- `git_mock.sh`, `wget_mock.sh` and `MockApp.app.tar.gz` are stand-ins for tool and app installs.
