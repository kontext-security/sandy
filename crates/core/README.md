# sandy-core

Validated policy and launch contracts used by Sandy.

Trusted product boundaries resolve ambient filesystem identity into a
`ResolvedPolicyDraft`. Core finalization then bounds and normalizes those typed
contributions, derives required ancestor protections, and produces the
`ValidatedPolicy` accepted by enforcement. Decoded launch manifests bypass
that trusted assembly step and are validated strictly without repair.

Agent-specific defaults are product data in `sandy-cli`; they are deliberately
outside this platform-neutral validation crate. File loading, home expansion,
existence checks, and canonicalization stay in the owning product boundary.

This is an implementation package published so the supported `sandy-sandbox`
facade can be distributed through the Rust package registry. Direct
`sandy-core` consumption is not covered by Sandy's compatibility guarantee;
types re-exported by the facade are guaranteed only through that facade.
Applications should depend on `sandy-sandbox` and import its `sandy` library
instead.
