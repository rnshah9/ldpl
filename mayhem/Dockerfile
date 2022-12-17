FROM ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y make g++ clang

COPY . /usr/src/myapp
WORKDIR /usr/src/myapp
ENV DESTDIR=/install
RUN make && make install
RUN clang++ /usr/src/myapp/mayhem/fuzz_trim.cpp -fsanitize=fuzzer,address -I /usr/src/myapp/src/libraries/ -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_trim
