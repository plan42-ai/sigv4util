PROJECT_MAJOR_VERSION := 1
PROJECT_MINOR_VERSION := 0

# Check if GITHUB_RUN_NUMBER and GITHUB_RUN_ATTEMPT are defined
ifdef GITHUB_RUN_NUMBER
    PROJECT_PATCH_VERSION := $(GITHUB_RUN_NUMBER)
    ifeq ($(GITHUB_RUN_ATTEMPT), 1)
        PROJECT_ADDITIONAL_VERSION := ""
    else
        PROJECT_ADDITIONAL_VERSION := "-$(GITHUB_RUN_ATTEMPT)"
    endif
else
    PROJECT_PATCH_VERSION := 0
    PROJECT_ADDITIONAL_VERSION := ""
endif

VERSION = "$(PROJECT_MAJOR_VERSION).$(PROJECT_MINOR_VERSION).$(PROJECT_PATCH_VERSION)$(PROJECT_ADDITIONAL_VERSION)"

.PHONY: fmt
fmt:
	go fmt ./...	

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go clean -testcache
	go test --race -v ./...

.PHONY: build
build:
	go build ./...

.PHONY: cover
cover:
	go test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: tag
tag:
	git tag v$(VERSION)
	git push origin v$(VERSION)
