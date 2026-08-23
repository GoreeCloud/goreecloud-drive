.PHONY: fmt test vet verify run

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

vet:
	go vet ./...

verify:
	@test -z "$$(gofmt -l ./cmd ./internal)" || (echo "gofmt required"; gofmt -l ./cmd ./internal; exit 1)
	go vet ./...
	go test ./...

run:
	go run ./cmd/server
