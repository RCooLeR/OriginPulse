# Docker Compose

## Target containers

```text
originpulse
postgres
ollama
```

## Example `docker/docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: originpulse
      POSTGRES_USER: originpulse
      POSTGRES_PASSWORD: originpulse_dev_password
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "55432:5432"

  ollama:
    image: ollama/ollama
    volumes:
      - ollama:/root/.ollama
    ports:
      - "11434:11434"

  originpulse:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    command: ["server", "-config", "/app/config.yml"]
    environment:
      ORIGINPULSE_CONFIG: /app/config.yml
      DATABASE_URL: postgres://originpulse:originpulse_dev_password@postgres:5432/originpulse?sslmode=disable
      OLLAMA_BASE_URL: http://ollama:11434
      PANTHEON_EMAIL: you@example.com
      PANTHEON_SSH_KEY_PATH: /run/secrets/pantheon_ssh_key
      LOG_LEVEL: debug
    volumes:
      - ../config.yml:/app/config.yml:ro
      - originpulse_data:/data
    secrets:
      - pantheon_ssh_key
    depends_on:
      - postgres
      - ollama
    ports:
      - "8080:8080"

secrets:
  pantheon_ssh_key:
    file: ../secrets/pantheon_ssh_key

volumes:
  pgdata:
  ollama:
  originpulse_data:
```

## Example backend `docker/Dockerfile`

```dockerfile
FROM golang:1.22-alpine AS build

WORKDIR /src
RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/originpulse ./cmd/originpulse

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata openssh-client
WORKDIR /app

COPY --from=build /out/originpulse /usr/local/bin/originpulse

VOLUME ["/data"]

ENTRYPOINT ["originpulse"]
```

## Dev commands

```bash
docker compose -f docker/docker-compose.yml up --build
docker compose -f docker/docker-compose.yml exec originpulse originpulse check-config -config /app/config.yml
docker compose -f docker/docker-compose.yml exec originpulse originpulse collect -config /app/config.yml
```

For host-run development against the compose Postgres, use:

```bash
DATABASE_URL='postgres://originpulse:originpulse_dev_password@127.0.0.1:55432/originpulse?sslmode=disable'
```

## Production notes

- Do not expose Postgres publicly.
- Do not expose Ollama publicly.
- Put proxy behind HTTPS.
- Use Docker secrets or environment injection for Pantheon credentials.
- Mount `/data/raw` and `/data/combined` to persistent storage.
- Back up Postgres and combined logs.
