# PE Section Yapper

Tiny Rust lab for poking at Windows PE section headers.

It takes an `.exe`, walks the real PE section table, blanks section names, and adds READ/WRITE/EXECUTE flags while preserving section bytes so the output can still open.

```powershell
cargo run -- input.exe output.exe
```

Note: this is for learning PE headers, not for building a packer.
