# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM docker.io/library/golang:1.22.4-alpine as builder

WORKDIR /app

# Download necessary Go modules
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# build an app
COPY . .
RUN CGO_ENABLED=0 go build -v -o /opi-sztp-agent

# Run tests
RUN go test -v ./...

# second stage to reduce image size
FROM alpine:3.20

RUN apk add --no-cache --no-check-certificate dbus curl && rm -rf /var/cache/apk/*

COPY --from=builder /opi-sztp-agent /

CMD ["sh", "-c", "dbus-daemon --system && /opi-sztp-agent"]
