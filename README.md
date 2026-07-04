# PE Section Yapper

Tiny Rust lab for poking at Windows PE section headers.

It takes an `.exe`, walks the real PE section table, zlib-compresses raw section bytes in place, blanks section names, and adds READ/WRITE/EXECUTE flags.

```powershell
cargo run -- input.exe output.exe
```

Note: the output is for learning and inspection, not a runnable packer. A runnable packed binary would need a loader stub that restores code/data in memory before jumping to the original entrypoint.
