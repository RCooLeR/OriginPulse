FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY . .
RUN mkdir -p /out/data
RUN if [ ! -d vendor ]; then go mod download; fi
RUN if [ -d vendor ]; then \
      CGO_ENABLED=0 go build -mod=vendor -o /out/originpulse ./cmd/originpulse; \
    else \
      CGO_ENABLED=0 go build -o /out/originpulse ./cmd/originpulse; \
    fi

FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=build --chown=nonroot:nonroot /out/originpulse /usr/local/bin/originpulse
COPY --from=build --chown=nonroot:nonroot /out/data /app/data
COPY --chown=nonroot:nonroot config.example.yml /app/config.example.yml
COPY --chown=nonroot:nonroot assets /app/assets

VOLUME ["/app/data"]
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["originpulse"]
CMD ["server", "-config", "/app/config.example.yml"]
