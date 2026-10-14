# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in `uu_file`, please report it via Coordinated Vulnerability Disclosure rather than opening a public issue.

## Hardening Guarantees

`uu_file` inspects untrusted, adversarial binary blobs by design. It implements defense-in-depth protections:
- **Memory Safety**: Clean-room implementation in safe Rust.
- **ReDoS Immunity**: Safe `regex` DFA backend with linear $O(n)$ time bounds.
- **Recursion Ceilings**: Hard limit on nested rules (`MAX_RECURSION_DEPTH = 32`).
- **Decompression Bomb Protection**: Transparent decompression streaming is strictly capped (1 MiB).
- **Non-blocking I/O**: Special files and FIFOs are opened with non-blocking checks to prevent unbounded hangs.
- **Bounded Resource Reads**: File header reads are bounded by `-P bytes` (default 7 MiB).
