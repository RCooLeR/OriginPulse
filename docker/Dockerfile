# syntax=docker/dockerfile:1
# check=error=true

FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS build

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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

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
