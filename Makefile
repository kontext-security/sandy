.DEFAULT_GOAL := help

.PHONY: help build test test-live fmt fmt-check clippy deny package-check formula-check release-version-check check run

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make <target>\n\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the Sandy binary.
	cargo build --workspace --locked

test: ## Run workspace tests.
	cargo test --workspace --locked

test-live: ## Run sacrificial macOS Seatbelt enforcement tests.
	cargo test -p sandy-cli --test live_macos --locked -- --ignored --test-threads=1
	cargo test -p sandy-sandbox --test live_macos --features live-tests --locked

fmt: ## Format Rust sources.
	cargo fmt --all

fmt-check: ## Check Rust formatting.
	cargo fmt --all --check

clippy: ## Run strict Clippy checks.
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

deny: ## Check dependency advisories, licenses, and sources.
	cargo deny check

package-check: ## Verify publishable packages and the external consumer fixture.
	cargo package --workspace --exclude sandy-cli --allow-dirty --locked
	cargo check --manifest-path tests/package-consumer/Cargo.toml --locked

formula-check: ## Validate the generated public Homebrew formula.
	./scripts/test-render-homebrew-formula.sh

release-version-check: ## Validate release metadata against every workspace package.
	./scripts/test-verify-release-version.sh

check: fmt-check clippy test deny package-check formula-check release-version-check ## Run the authoritative local verification.

run: ## Run Sandy's help from source.
	cargo run -p sandy-cli -- --help
