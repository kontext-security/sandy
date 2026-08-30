# sandy-seatbelt

Typed macOS policy compilation and native enforcement used by Sandy.

This is an implementation package published so the supported `sandy-sandbox`
facade can be distributed through the Rust package registry. Its public Rust
surface, generated policy source, and private macOS boundary are not covered by
Sandy's compatibility guarantee. Applications should depend on `sandy-sandbox`
and import its `sandy` library instead.
