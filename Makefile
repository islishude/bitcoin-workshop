clean:
	docker compose down
	rm -rf ./data/regtest

start:
	docker compose up -d
