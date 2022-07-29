FROM alpine:latest as builder

RUN apk add --no-cache make g++

COPY . /usr/src/myapp
WORKDIR /usr/src/myapp
ENV DESTDIR=/install
RUN make && make install

FROM alpine:latest as package
COPY --from=builder /install /install
