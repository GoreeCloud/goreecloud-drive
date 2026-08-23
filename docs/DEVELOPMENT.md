# Development

## Prerequisites

- Go 1.25 or newer compatible toolchain.

## Run

```sh
cp .env.example .env
make run
```

The current server reads environment variables directly. Export values from `.env` with your preferred local development mechanism; the application intentionally does not add an environment-file dependency.

Open `http://127.0.0.1:8080`.

## Validate

```sh
make verify
```

This runs formatting verification, `go vet`, and all Go tests.

## Source workflow

Material work belongs on a short-lived branch, is reviewed through a pull request, and must pass the applicable exact-head checks before merge. A merge is not a release, deployment, production acceptance, or Stable promotion.
