.PHONY: up down logs rebuild clean-db zip
up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

rebuild:
	docker compose down && docker compose up --build -d

clean-db:
	docker compose down -v && docker compose up --build -d
