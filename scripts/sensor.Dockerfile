FROM golang:1.26.11-alpine3.23@sha256:db99415e2625ce0ee03eed09edf7f32ae8c58dc399f28cc602a87fe7238119e4 AS build
RUN apk add --no-cache build-base linux-headers
WORKDIR /src
COPY sensor/go.mod sensor/go.sum ./
RUN go mod download
COPY sensor/ .
COPY proto/ /proto/
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=1 go test ./... && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/c2hunter-sensor ./cmd/c2hunter-sensor
FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache ca-certificates && adduser -D -u 65532 sensor
COPY --from=build /out/c2hunter-sensor /usr/local/bin/c2hunter-sensor
USER sensor
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/c2hunter-sensor"]
