# The build stage runs on the builder's platform and Go cross-compiles, so a
# multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.2 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/barbackend ./cmd/barbackend

# The binary needs only CA certificates at runtime.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/barbackend /barbackend
ENV GIN_MODE=release
EXPOSE 8080
ENTRYPOINT ["/barbackend"]
CMD ["serve"]
