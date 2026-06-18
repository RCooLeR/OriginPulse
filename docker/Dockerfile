FROM golang:1.26-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates git tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/originpulse ./cmd/originpulse

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata openssh-client
WORKDIR /app

COPY --from=build /out/originpulse /usr/local/bin/originpulse
COPY config.example.yml /app/config.example.yml

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["originpulse"]
CMD ["server", "-config", "/app/config.example.yml"]
