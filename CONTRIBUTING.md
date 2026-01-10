# Contributing

Thanks for your interest in TitanDNS. We welcome issues and pull requests.

## Before you start

- Search existing issues and discussions to avoid duplicates.
- For large changes, open an issue first to align on scope.

## Development

- Use Rust stable.
- Run formatting and checks before PR:

```
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## Pull Requests

- Keep PRs focused and small when possible.
- Add tests for behavior changes.
- Update README/CHANGELOG if user-visible changes are introduced.

## Reporting Bugs

Please include:
- Steps to reproduce
- Expected vs actual results
- Environment details (OS, Rust version)
