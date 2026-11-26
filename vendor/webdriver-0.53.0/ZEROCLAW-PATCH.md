# WebDriver dependency patch

Source is the published `webdriver 0.53.0` archive from crates.io.
Archive SHA-256 is `91d53921e1bef27512fa358179c9a22428d55778d2c2ae3c5c37a52b82ce6e92`.
The archive records source revision `2c83250e67d85c2a172670b08cd88753d1552d91`.
The MPL-2.0 license text accompanies the original source headers.

The patch removes the unused `cookie 0.16` dependency and its `extern crate`
declaration. WebDriver's protocol cookie structures are defined in the crate.
This removes the vulnerable dependency identified by RUSTSEC-2026-0594.
The logging macro import uses the same `server` feature as its callers.

Remove this checkout patch when Fantoccini can use a published WebDriver
release that resolves without the vulnerable cookie version.
