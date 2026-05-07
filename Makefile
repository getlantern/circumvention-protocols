.PHONY: build install test clean validate

BIN_DIR ?= $(HOME)/.local/bin
BUILD_DIR := build

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/protocols-mcp ./cmd/protocols-mcp

install: build
	mkdir -p $(BIN_DIR)
	cp $(BUILD_DIR)/protocols-mcp $(BIN_DIR)/protocols-mcp

test:
	go test ./...

# Validate every YAML against the JSON Schema. Requires `ajv` (npx ajv-cli).
validate:
	@for f in protocols/*.yaml; do \
		[ "$$(basename $$f)" = "_template.yaml" ] && continue; \
		echo "validating $$f"; \
		yq -o=json "$$f" | npx --yes ajv-cli validate -s schema/protocol.schema.json -d - || exit 1; \
	done

clean:
	rm -rf $(BUILD_DIR)
