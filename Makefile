BINARY=bin/atl
GO=go

.PHONY: build test lint clean deps vet

build:
	$(GO) build -o $(BINARY) ./cmd/atl

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint: vet

clean:
	rm -rf bin/

deps:
	$(GO) mod tidy
	$(GO) mod download
