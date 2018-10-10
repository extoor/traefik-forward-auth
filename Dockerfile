FROM golang:1.11-alpine as builder

ADD . ${GOPATH}/src/app

# Add libraries
RUN apk add --no-cache git \
    && go get -d -v app

# Copy & build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /traefik-forward-auth app

FROM alpine:3.8
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /traefik-forward-auth /usr/local/bin/
ENTRYPOINT ["traefik-forward-auth"]
