# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2022 Dell Inc, or its subsidiaries.

FROM docker.io/library/golang:1.21.3-alpine as builder

WORKDIR /app

# Download necessary Go modules
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# build an app
COPY . .
RUN go build -v -o /opi-sztp-agent && CGO_ENABLED=0 go test -v ./...

# second stage to reduce image size
FROM alpine:3.20

RUN apk add --no-cache --no-check-certificate curl && rm -rf /var/cache/apk/*

COPY --from=builder /opi-sztp-agent /

CMD [ "/opi-sztp-agent" ]
