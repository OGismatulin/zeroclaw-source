# Temporary SQLite compatibility patch

Source: published matrix-sdk-sqlite 0.19.1 archive from crates.io.
Archive SHA-256: `8d4271e06d52a17bc6ec39b5a2985b65dcced737969fac3678967783656edb34`.
Release source commit: `b18166c68bb958a21f0bca8b2d8320cb53583362`.
License: Apache-2.0; see LICENSE and original source headers.

Modified files: Cargo.toml and Cargo.toml.orig. The rusqlite requirement
changes from 0.40.2 to 0.41.1, matching official upstream commit
18757f7e08ecad6c959a706c725e9875b0e413b3. Rust sources and SQL migrations
remain identical to the published archive. Cargo.lock and Cargo cache
metadata are omitted; README and LICENSE come from the release source.

This checkout-only bridge enables patched libsqlite3-sys 0.39.1 / SQLite
3.54.1 for RUSTSEC-2026-0459. A root crates.io patch is not inherited by
registry consumers: do not publish this dependency graph to crates.io.

Remove the directory, workspace exclusion and patch once a published
matrix-sdk-sqlite release accepts rusqlite 0.41.1 or later. Keep the
SQLite security-floor regression and do not restore the advisory waiver.
