FROM golang:1.17-alpine AS builder

ENV GOPROXY https://proxy.golang.org,direct

ENV WORKDIR /app
WORKDIR ${WORKDIR}

RUN apk add --no-cache make upx

RUN mkdir -p ${GOPATH}/src/ && \
    mkdir -p ${GOPATH}/bin/

ENV PATH ${GOPATH}/bin:/usr/local/go/bin:$PATH

RUN go install golang.org/x/lint/golint@latest && \
    go install github.com/jteeuwen/go-bindata/go-bindata@latest

COPY go.mod go.sum Makefile ./
RUN make deps

COPY ./ ./
RUN make build
RUN make compress

FROM alpine:3.13

RUN apk add --no-cache ca-certificates && update-ca-certificates
RUN apk add --no-cache tzdata

ENV TZ America/Los_Angeles

ENV BUILDER_PATH /app
ENV WORKDIR /app
WORKDIR ${WORKDIR}

#COPY --from=builder ${BUILDER_PATH}/build/bin/pgrok /usr/local/bin/pgrok
COPY --from=builder ${BUILDER_PATH}/build/bin/pgrokd /usr/local/bin/pgrokd

EXPOSE 80
EXPOSE 443
EXPOSE 4443

ENTRYPOINT ["/usr/local/bin/pgrokd"]
CMD []
