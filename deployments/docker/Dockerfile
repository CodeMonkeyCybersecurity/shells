FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o webscan .

FROM golang:1.21-alpine AS tools

RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates \
    nmap \
    nmap-scripts \
    openssl \
    curl \
    bash \
    git \
    python3 \
    py3-pip \
    nodejs \
    npm \
    jq

# Copy Go tools from builder
COPY --from=tools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /go/bin/httpx /usr/local/bin/httpx

# Install Node.js tools
RUN npm install -g retire @apideck/better-ajv-errors linkfinder

# Update nuclei templates
RUN nuclei -update-templates

WORKDIR /app

COPY --from=builder /app/webscan /usr/local/bin/webscan

RUN adduser -D -g '' webscan
USER webscan

EXPOSE 8080

ENTRYPOINT ["webscan"]