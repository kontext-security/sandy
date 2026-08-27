.DEFAULT_GOAL := help

.PHONY: help build test fmt fmt-check clippy deny formula-check check run

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make <target>\n\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build the Sandy binary.
	cargo build --workspace --locked

test: ## Run workspace tests.
	cargo test --workspace --locked

fmt: ## Format Rust sources.
	cargo fmt --all

fmt-check: ## Check Rust formatting.
	cargo fmt --all --check

clippy: ## Run strict Clippy checks.
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

deny: ## Check dependency advisories, licenses, and sources.
	cargo deny check

formula-check: ## Validate the generated public Homebrew formula.
	./scripts/test-render-homebrew-formula.sh

check: fmt-check clippy test deny formula-check ## Run the authoritative local verification.

run: ## Run Sandy's help from source.
	cargo run -p sandy-cli -- --help
