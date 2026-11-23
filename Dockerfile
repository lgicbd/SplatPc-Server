FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/splatoon-nex ./cmd/splatoon-nex

FROM alpine:3.21

RUN apk add --no-cache wireguard-tools iptables iproute2 ca-certificates tzdata

COPY --from=builder /out/splatoon-nex /usr/local/bin/splatoon-nex
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /var/lib/splatoon /var/log/splatoon /etc/splatoon

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--config", "/etc/splatoon/server.json", "--log", "/var/log/splatoon/nexserver.log"]
