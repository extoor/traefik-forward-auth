FROM golang:1.11-alpine as builder

# Setup
RUN mkdir /app
WORKDIR /app

ADD . ${GOPATH}/src/app

# Add libraries
RUN apk add --no-cache git && \
    go get -d -v app
    apk del git

# Copy & build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /traefik-forward-auth app

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
