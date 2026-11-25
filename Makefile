GO ?= go
PYTHON ?= python3

.PHONY: test test-go test-python build build-all-linux docker-build

test: test-go test-python

test-go:
	$(GO) test -timeout 30s ./...

test-python:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -v

build:
	$(PYTHON) build.py --output dist

build-all-linux:
	$(PYTHON) build.py --all-linux --output dist

docker-build:
	docker build --output type=local,dest=dist-linux .
