.PHONY: help all style test release ruff-check-fix format check-branch check-type check-clean patch minor major

help:
	awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## General Targets
all: style test  ## Format, lint and test

## Format and lint code
style: format ruff-check-fix ## Format and lint code

## Testing
test: ## Run tests
	cd tests && pytest


## Code Formatting
format: ## Format code using ruff
	ruff format .

## Code Linting
ruff-check-fix:  ## Lint code using ruff
	ruff check --fix .

## Release Operations
release: check-type check-branch pre-release $(TYPE) post-release  ## Perform a release
	@echo "Release complete"





######### Helpers (not meant to be called directly) #########
# release checking
pre-release: check-branch style check-clean test
post-release: push


# Check if the current Git branch is 'main'
check-branch:
	@if [ "$(shell git rev-parse --abbrev-ref HEAD)" != "main" ]; then \
		echo "You are not on the 'main' branch. Aborting."; \
		exit 1; \
	fi

check-type:
	@if [ -z "$(TYPE)" ]; then \
		echo "ERROR: Specify 'patch', 'minor', 'major' by running 'make release TYPE=<type>'"; \
		exit 1; \
	fi
	@if [ "$(TYPE)" != "patch" -a "$(TYPE)" != "minor" -a "$(TYPE)" != "major" ]; then \
		echo "ERROR: Invalid TYPE set. Specify 'patch', 'minor', 'major' by running 'make release TYPE=<type>'"; \
		exit 1; \
	fi

## Git Operations
push:
	git push && git push --tags


## Git Status Check
check-clean:
	@if [ -n "$(shell git status --porcelain)" ]; then \
		echo "Your Git working directory is not clean. Commit or stash your changes before proceeding."; \
		exit 1; \
	fi



patch:
	bump2version --dry-run --verbose patch
	bump2version patch

minor: # hidden # bump minor version
	bump2version --dry-run --verbose minor
	bump2version minor

major: # hidden # bump major version
	bump2version --dry-run --verbose major
	bump2version major