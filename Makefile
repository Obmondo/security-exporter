NAME = obmondo-security-exporter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet lint clean gen-eol docker-build docker-up docker-down docker-logs

build: gen-eol
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags="-extldflags=-static -s -w -X main.Version=$(VERSION)" -o dist/$(NAME) ./cmd/

gen-eol:
	go generate ./internal/eol/...

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf dist/

docker-build:
	docker compose build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f
