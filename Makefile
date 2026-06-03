# Makefile — D-HotStuff build system.
#
# Common variables can be overridden on the command line, e.g.:
#   make keys N=7
#   make deploy N=4
#
# Prerequisites (install once):
#   protoc           https://github.com/protocolbuffers/protobuf/releases
#   protoc-gen-go    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   protoc-gen-go-grpc go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#   golangci-lint    https://golangci-lint.run/usage/install/

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

# Number of replicas for key generation and local deployment.
N ?= 4

# Output directories.
BIN_DIR      := ./bin
PROTO_GEN    := ./proto/gen

# Proto source and include paths.
PROTO_SRC    := proto/dhotstuff.proto
PROTO_PATHS  := \
	--proto_path=. \
	--proto_path=local/hotstuff/internal/proto \
	--proto_path=local/hotstuff \
	--proto_path=$(shell go env GOPATH)/pkg/mod/github.com/relab/gorums@v0.10.0

# Go binary targets (adjust as you add cmd/ sub-packages).
CMD_TARGETS  := ./cmd/dhotstuff ./cmd/client ./cmd/keygen

# Benchmark package (metrics package — adjust if it moves).
BENCH_PKG    := ./internal/metrics/

# Test flags.
TEST_FLAGS   := -race -count=1

# ---------------------------------------------------------------------------
# Phony declarations — targets that don't correspond to real files.
# ---------------------------------------------------------------------------
.PHONY: proto build test bench lint keys deploy clean all

# Default target: generate, then build.
all: proto build

# ---------------------------------------------------------------------------
# proto — generate Go stubs from proto/dhotstuff.proto into proto/gen/
#
# Output layout:
#   proto/gen/dhotstuff.pb.go      — message types
#   proto/gen/dhotstuff_grpc.pb.go — gRPC service client/server stubs
#
# The --go_opt=module=... flag strips the module prefix from the output path so
# files land in $(PROTO_GEN) regardless of the Go module name.
# ---------------------------------------------------------------------------
proto:
	@echo "==> Generating protobuf stubs → $(PROTO_GEN)"
	@mkdir -p $(PROTO_GEN)
	protoc $(PROTO_PATHS) \
		--go_out=$(PROTO_GEN) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_GEN) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_SRC)
	@echo "    done."

# ---------------------------------------------------------------------------
# build — compile all cmd/ binaries into ./bin/
#
# Binaries produced:
#   bin/dhotstuff  — replica daemon
#   bin/client     — benchmark / workload client
#   bin/keygen     — ECDSA P-256 key-pair generator
#
# CGO_ENABLED=0 produces fully static binaries (useful for Docker).
# ---------------------------------------------------------------------------
build:
	@echo "==> Building binaries → $(BIN_DIR)/"
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -o $(BIN_DIR)/ $(CMD_TARGETS)
	@echo "    done: $$(ls $(BIN_DIR)/)"

# ---------------------------------------------------------------------------
# test — run the full test suite with the race detector.
#
# -count=1 disables test result caching so every run is fresh.
# ---------------------------------------------------------------------------
test:
	@echo "==> Running tests (race detector on)"
	go test $(TEST_FLAGS) ./...

# ---------------------------------------------------------------------------
# bench — run benchmarks in the metrics package.
#
# -run='^$$' skips all unit tests so only benchmarks execute.
# -benchmem reports allocations per operation alongside ns/op.
# ---------------------------------------------------------------------------
bench:
	@echo "==> Running benchmarks in $(BENCH_PKG)"
	go test -bench=. -benchmem -run='^$$' $(BENCH_PKG)

# ---------------------------------------------------------------------------
# lint — static analysis via golangci-lint.
#
# Configuration is read from .golangci.yml if present.
# Exit code 1 means lint errors were found; fix them before merging.
# ---------------------------------------------------------------------------
lint:
	@echo "==> Running golangci-lint"
	golangci-lint run ./...

# ---------------------------------------------------------------------------
# keys — generate ECDSA P-256 key pairs for N replicas (default N=4).
#
# Calls scripts/gen_keys.sh which writes:
#   keys/P<i>.pem      — private key (PEM, mode 0600)
#   keys/P<i>.pub.pem  — public key  (PEM)
#   keys/P<i>.pub.der.b64 — base64-encoded DER (paste into genesis.toml)
#
# Usage:
#   make keys        # generates keys for P1–P4
#   make keys N=7    # generates keys for P1–P7
# ---------------------------------------------------------------------------
keys:
	@echo "==> Generating key pairs for $(N) replicas"
	@mkdir -p keys
	bash scripts/gen_keys.sh $(N)
	@echo "    Keys written to keys/  — paste .pub.der.b64 values into genesis.toml"

# ---------------------------------------------------------------------------
# deploy — start a local N-replica cluster using Docker Compose or bare processes.
#
# Reads N from the environment or defaults to 4.
# Calls scripts/deploy_local.sh which handles:
#   - generating per-replica replica.toml files from a template
#   - starting N replica processes (or containers) in the background
#   - printing their Prometheus endpoints for scraping
#
# Usage:
#   make deploy         # deploy 4-replica cluster
#   N=7 make deploy     # deploy 7-replica cluster
# ---------------------------------------------------------------------------
deploy:
	@echo "==> Deploying local cluster with $(N) replicas"
	bash scripts/deploy_local.sh $(N)

# ---------------------------------------------------------------------------
# clean — remove generated artifacts.
#
# Does NOT remove keys/ or config/ — those are hand-crafted or secret material.
# ---------------------------------------------------------------------------
clean:
	@echo "==> Cleaning build artifacts"
	rm -rf $(BIN_DIR) $(PROTO_GEN)
	@echo "    done."
