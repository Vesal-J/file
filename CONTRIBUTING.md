# Contributing to uu_file

Thank you for your interest in contributing to `uu_file`!

## Clean-Room Engineering Policy

To preserve the MIT license and guarantee independent IP provenance:
- **Strict Clean-Room Development**: Absolutely zero code may be copied or derived from GPL/GNU implementations.
- Compatibility must be achieved strictly through public specifications, POSIX IEEE Std 1003.1, man pages, and BSD/MIT-licensed reference documentation.

## Code Standards & Style

1. **Format**: Format all code using `cargo fmt`.
2. **Clippy**: Ensure code passes `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
3. **Tests**: Add integration tests under `tests/` for any new flags or format classifiers.
4. **Safety**: Safe Rust is required. The core inspection engine must be 100% safe Rust.
