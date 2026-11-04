# syntax=docker/dockerfile:1
# check=error=true

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build

ARG TARGETOS
ARG TARGETARCH

ENV GOTOOLCHAIN=local

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,id=originpulse-go-mod,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN mkdir -p /out/data
RUN --mount=type=cache,id=originpulse-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=originpulse-go-build,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/originpulse ./cmd/originpulse

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

WORKDIR /app

COPY --link --from=build --chown=65532:65532 /out/originpulse /usr/local/bin/originpulse
COPY --link --from=build --chown=65532:65532 /out/data /app/data
COPY --link --chown=65532:65532 config.example.yml /app/config.example.yml
COPY --link --chown=65532:65532 assets /app/assets

VOLUME ["/app/data"]
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/originpulse"]
CMD ["server", "-config", "/app/config.example.yml"]
