FROM golang:1.11-alpine as builder

ARG APP_NAME=traefik-forward-auth

ADD . ${GOPATH}/src/${APP_NAME}

# Add libraries
RUN apk add --no-cache git \
    && go get -d -v ${APP_NAME}

# Copy & build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /traefik-forward-auth ${APP_NAME}

FROM alpine:3.8
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /traefik-forward-auth /usr/local/bin/
ENTRYPOINT ["traefik-forward-auth"]
