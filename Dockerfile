FROM golang:1.17-alpine as build
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN apk add --no-cache make git  curl

WORKDIR /go/src/github.com/netlify/gotrue

# Pulling dependencies
COPY ./Makefile ./go.* ./
RUN make deps

# Building stuff
COPY . /go/src/github.com/netlify/gotrue
RUN make build

ARG KAIGARA_VERSION=v1.0.10
RUN curl -Lo ./kaigara  https://github.com/openware/kaigara/releases/download/${KAIGARA_VERSION}/kaigara \
  && chmod +x ./kaigara

FROM alpine:3.15
RUN adduser -D -u 1000 netlify

RUN apk add --no-cache ca-certificates
COPY --from=build /go/src/github.com/netlify/gotrue/gotrue /usr/local/bin/gotrue
COPY --from=build /go/src/github.com/netlify/gotrue/kaigara /usr/local/bin/kaigara
COPY --from=build /go/src/github.com/netlify/gotrue/migrations /usr/local/etc/gotrue/migrations/

ENV GOTRUE_DB_MIGRATIONS_PATH /usr/local/etc/gotrue/migrations

USER netlify
CMD ["gotrue"]
