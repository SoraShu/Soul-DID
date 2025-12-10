-include .env

deploy: 
	forge script script/Deploy.s.sol:DeployScript \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast
	
interact:
	forge script script/Interact.s.sol:InteractScript \
		--rpc-url $(RPC_URL) \
		--broadcast