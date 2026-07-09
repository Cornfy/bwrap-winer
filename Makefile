# ==============================================================================
# 🛠️ bwrap-winer - Multi-Architecture GNU Makefile (Rust Static Compilation)
# ==============================================================================

# Variable Definitions
BINARY_NAME=bwrap-winer
BIN_DIR=bin
BUILD_DIR=builds

# Get Version Information (Automatically detected via Git)
GIT_TAG=$(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DEV_VERSION=$(GIT_TAG)-dev-$(GIT_COMMIT)

# ==============================================================================
# Execution Targets
# ==============================================================================

.PHONY: all setup build run release clean help

# Default Target
all: build

## setup: Check and install the required cross-compilation toolchain targets via rustup
setup:
	@echo "[bwrap-winer] Checking and installing target toolchains via rustup..."
	@rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null

## build: Build local developer native version to bin/ directory
build:
	@echo "[bwrap-winer] Building local developer version: $(DEV_VERSION)"
	@mkdir -p $(BIN_DIR)
	@cargo build --release
	@cp target/release/$(BINARY_NAME) $(BIN_DIR)/$(BINARY_NAME)
	@echo "[bwrap-winer] Local build complete: ./$(BIN_DIR)/$(BINARY_NAME)"

## run: Build and immediately execute local sandbox proxy help menu
run: build
	./$(BIN_DIR)/$(BINARY_NAME) --help

## release: Cross-compile multi-platform dependency-free static binaries to builds/ directory
release: setup
	@echo "[bwrap-winer] Preparing static release version: $(GIT_TAG)"
	@mkdir -p $(BUILD_DIR)
	
	@# Linux AMD64 (Static musl - uses Rust bundled musl runtime and LLD linker for dependency-free build)
	@echo " -> Linux AMD64 (Statically Linked)..."
	@RUSTFLAGS="-C link-self-contained=yes -C linker=rust-lld" \
		cargo build --release --target x86_64-unknown-linux-musl
	@cp target/x86_64-unknown-linux-musl/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64
	
	@# Linux ARM64 (Static musl - utilizes self-contained runtime and built-in LLD linker for seamless cross-compilation)
	@echo " -> Linux ARM64 (Statically Linked via rust-lld)..."
	@RUSTFLAGS="-C link-self-contained=yes -C linker=rust-lld" \
		cargo build --release --target aarch64-unknown-linux-musl
	@cp target/aarch64-unknown-linux-musl/release/$(BINARY_NAME) $(BUILD_DIR)/$(BINARY_NAME)_linux_arm64
	
	@echo ""
	@echo "[bwrap-winer] Statically compiled binaries are ready in ./$(BUILD_DIR):"
	@ls -lh $(BUILD_DIR)

## clean: Clean up Cargo and local build artifacts
clean:
	@echo "[bwrap-winer] Cleaning up build artifacts and cargo cache..."
	@cargo clean
	@rm -rf $(BIN_DIR)
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

## help: Show this help screen, automatically extracting target descriptions marked with '##'
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## .*' $(MAKEFILE_LIST) | sed -e 's/## //' | awk 'BEGIN {FS = ": "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
