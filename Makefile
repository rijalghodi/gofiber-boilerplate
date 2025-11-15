include .env
export $(shell sed 's/=.*//' .env)

start:
	@go run main.go http
lint:
	@golangci-lint run
swagger:
	@swag init --dir ./cmd,./internal --output ./docs
migration-%:
	@if [ ! -d "internal/database/migrations" ]; then mkdir -p internal/database/migrations; fi; \
	NEXT_NUM=$$(ls -1 internal/database/migrations/*.sql 2>/dev/null | sed -n 's/.*\/\([0-9]*\)_.*/\1/p' | sort -n | tail -1); \
	if [ -z "$$NEXT_NUM" ]; then NEXT_NUM=0; fi; \
	NEXT_NUM=$$((NEXT_NUM + 1)); \
	MIGRATION_FILE="internal/database/migrations/$${NEXT_NUM}_$(subst :,_,$*).sql"; \
	echo "-- +migrate Up" > "$$MIGRATION_FILE"; \
	echo "" >> "$$MIGRATION_FILE"; \
	echo "-- +migrate Down" >> "$$MIGRATION_FILE"; \
	echo "Created migration: $$MIGRATION_FILE"
migrate-up:
	@go run main.go migrate up $(word 2,$(MAKECMDGOALS))
migrate-down:
	@go run main.go migrate down $(word 2,$(MAKECMDGOALS))
docker:
	@docker-compose up --build
docker-down:
	@docker-compose down --rmi all --volumes --remove-orphans
docker-cache:
	@docker builder prune -f