# Contributing

Read [AGENTS.md](AGENTS.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[SECURITY.md](SECURITY.md) before changing enforcement code.

Keep changes focused and update behavior, tests, and documentation together.
Run:

```bash
make check
```

Changes to capabilities, policy rendering, the native boundary, bootstrap,
supervision, or Kontext compatibility also require the live macOS tests:

```bash
cargo test -p sandy-cli --test live_macos -- --ignored
```

Those tests must run directly on macOS, not from inside another sandbox.

Use a Conventional Commit title for each pull request. Pull requests are
squash-merged so Release Please sees exactly one changelog-bearing commit per
change; do not use merge commits or rebase merges on `main`.

Release publication requires the `HOMEBREW_TAP_TOKEN` Actions secret. Use a
fine-grained token limited to `kontext-security/homebrew-tap` with Contents
read/write permission; do not store a broad personal token for this purpose.
After fixing a failed release workflow, dispatch `.github/workflows/release.yml`
for the existing tag from `main` instead of rerunning the old workflow revision.
