include .env

.DEFAULT_GOAL := help

help: ## Show this help
	@echo ""
	@echo "Specify a command. The choices are:"
	@echo ""
	@grep -hE '^[0-9a-zA-Z_-]+:.*?## .*$$' ${MAKEFILE_LIST} | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;36m%-20s\033[m %s\n", $$1, $$2}'
	@echo ""

build: ## Build the smart contracts
	forge build

lint: ## Lint the smart contracts
	forge lint

test: ## Run the tests and generate coverage report
	forge coverage --skip script

anvil: ## Start Anvil local Ethereum node
	anvil

deploy: ## Deploy the smart contracts
	forge script script/Deploy.s.sol:DeployScript \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast
	
interact: ## Interact with the deployed smart contracts
	forge script script/Interact.s.sol:InteractScript \
		--rpc-url $(RPC_URL) \
		--broadcast

client-user: ## Start the user client
	uv run client/user.py

client-issuer: ## Start the issuer client
	uv run client/issuer.py

client-admin: ## Start the admin client
	uv run client/admin.py

web: ## Start the DID Viewer web application
	uv run web/main.py

.PHONY: help
