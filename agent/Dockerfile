FROM golang:1.23-alpine AS builder

WORKDIR /workspace
COPY agent ./agent
RUN cd agent && go build -o /secos-agent ./cmd/secos-agent

FROM alpine:3.20

WORKDIR /workspace
COPY --from=builder /secos-agent /usr/local/bin/secos-agent
COPY fixtures ./fixtures
COPY agent/config.sample.json ./agent/config.sample.json

CMD ["secos-agent", "-config", "/workspace/agent/config.sample.json"]
