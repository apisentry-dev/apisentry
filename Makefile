BINARY   = apisentry
VERSION  = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -ldflags "-s -w -X main.version=$(VERSION)"
DIST     = dist

.PHONY: build build-all build-docker test lint clean

## Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) .

## Cross-compile for all platforms
build-all: clean
	mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64    .
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o $(DIST)/$(BINARY)-linux-arm64    .
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-amd64   .
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o $(DIST)/$(BINARY)-darwin-arm64   .
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe .

## Build Docker image
build-docker:
	docker build -t apisentry:$(VERSION) -t apisentry:latest .

## Run tests
test:
	go test ./... -v -timeout 60s

## Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## Remove build artifacts
clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe
