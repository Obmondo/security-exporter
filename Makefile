NAME=obmondo-security-exporter

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags="-extldflags=-static -s -w" -o dist/$(NAME) ./cmd/

test:
	go test ./...

clean:
	rm -rf dist/
