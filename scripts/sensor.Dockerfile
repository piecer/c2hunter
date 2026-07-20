FROM golang:1.23.6-alpine3.21 AS build
RUN apk add --no-cache build-base linux-headers
WORKDIR /src
COPY sensor/go.mod sensor/go.sum ./
RUN go mod download
COPY sensor/ .
COPY proto/ /proto/
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=1 go test ./... && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" -o /out/c2hunter-sensor ./cmd/c2hunter-sensor
FROM alpine:3.21.2
RUN apk add --no-cache ca-certificates && adduser -D -u 65532 sensor
COPY --from=build /out/c2hunter-sensor /usr/local/bin/c2hunter-sensor
USER sensor
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/c2hunter-sensor"]
