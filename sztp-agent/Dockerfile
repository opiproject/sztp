# syntax=docker/dockerfile:1

# Alpine is chosen for its small footprint
# compared to Ubuntu
FROM docker.io/library/golang:1.19.4-alpine

WORKDIR /app

# Download necessary Go modules
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# build an app
COPY . .
RUN go build -v -o /opi-sztp-agent && CGO_ENABLED=0 go test -v ./...

# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /opi.pem /opi.pem
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/my_cert.pem /my_cert.pem
# hadolint ignore=DL3022
COPY --from=ghcr.io/opiproject/opi-sztp-server:main /tmp/sztpd-simulator/pki/client/end-entity/private_key.pem /private_key.pem
# TODO: consider generating iDevID certificates using https://github.com/usnistgov/iDevIDCerts

CMD [ "/opi-sztp-agent" ]
