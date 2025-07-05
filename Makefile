include .envrc

APP = sba-user-accounts
GOBASE = $(shell pwd)
GOBIN = $(GOBASE)/build/bin
LINT_PATH = $(GOBASE)/build/lint
MAIN_APP = $(GOBASE)/cmd
MIGRATIONS_PATH=$(GOBASE)/migrations

# Default database connection details (matches docker-compose.yml)
DB_USER ?= admin
DB_PASSWORD ?= adminpassword
DB_NAME ?= sba_users
DB_HOST ?= localhost
DB_PORT ?= 5432
DB_ADDR ?= postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable


help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deps: ## Fetch required dependencies
	go mod tidy -compat=1.22
	go mod download

build: ## Build the application
	go build -o $(GOBIN)/$(APP) $(MAIN_APP)

run: build ## Build and run program
	cd $(MAIN_APP) && go run .

lint: install-golangci ## Linter for developers
	$(LINT_PATH)/golangci-lint run --timeout=5m -c .golangci.yml

lint-fix:
	$(LINT_PATH)/golangci-lint run --timeout=5m -c .golangci.yml --fix

install-golangci: ## Install the correct version of lint
	@GOBIN=$(LINT_PATH) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.58.1

migrate-up: ## Run the migration up
	@/home/businge-bisanga/go/bin/migrate -path=$(MIGRATIONS_PATH) -database=$(DB_ADDR) up $(filter-out $@,$(MAKECMDGOALS))

migrate-down: ## Run the migration down
	@/home/businge-bisanga/go/bin/migrate -path=$(MIGRATIONS_PATH) -database=$(DB_ADDR) down

migration: ## Create a new migration
	@/home/businge-bisanga/go/bin/migrate create -ext sql -dir $(MIGRATIONS_PATH) -seq $(filter-out $@,$(MAKECMDGOALS))		

docker-up: ## Run the docker-compose
	docker compose up -d

docker-down: ## Stop the docker-compose
	docker compose down

docker-restart: ## Restart the docker-compose
	docker-compose restart

# run-tests: ## Run tests 
# 	cd $(TEST_PATH) && go test .
# test-cover: ## Run tests with coverage
# 	cd $(TEST_PATH) && go test -cover

# test-coverage: ## Run tests and generate coverage profile
# 	cd $(TEST_PATH) && go test -coverprofile=coverage.out

# test-coverage-browser: ## Check the test coverage in the browser
# 	cd $(TEST_PATH) && go tool cover -html=coverage.out -o /tmp/coverage.html && wslview /tmp/coverage.html
