FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
# COPY go.sum ./ # No dependencies yet, so go.sum might not exist or be needed yet.

RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /hls-proxy

FROM alpine:latest

WORKDIR /

COPY --from=builder /hls-proxy /hls-proxy

EXPOSE 8080

ENTRYPOINT ["/hls-proxy"]
