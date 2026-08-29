# sandy-core

Validated policy and launch contracts used by Sandy.

This is an implementation package published so the supported `sandy-sandbox`
facade can be distributed through the Rust package registry. Direct
`sandy-core` consumption is not covered by Sandy's compatibility guarantee;
types re-exported by the facade are guaranteed only through that facade.
Applications should depend on `sandy-sandbox` and import its `sandy` library
instead.
