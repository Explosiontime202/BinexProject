FROM debian:bullseye

RUN apt update -y && apt upgrade -y && apt install -y build-essential wget cmake

COPY fnetd /bin/fnetd

## Add dummy get_flag
COPY tests/get_flag.c /bin/get_flag.c
RUN gcc -O3 /bin/get_flag.c -o /bin/get_flag
RUN rm /bin/get_flag.c

## Use course libc
COPY tests/libc-2.31.so /lib/x86_64-linux-gnu/libc-2.31-bx.so
RUN ln -sf /lib/x86_64-linux-gnu/libc-2.31-bx.so /lib/x86_64-linux-gnu/libc.so.6

RUN useradd -m pwn

COPY . /home/pwn/source

# compile vuln in debug mode
RUN mkdir /home/pwn/debug
WORKDIR /home/pwn/debug
RUN DISABLE_PRESENTATION_BUILD=true cmake /home/pwn/source -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug
RUN make

RUN mkdir /home/pwn/release
WORKDIR /home/pwn/release
RUN DISABLE_PRESENTATION_BUILD=true cmake /home/pwn/source -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
RUN make

RUN chown -R pwn:pwn /home/pwn

ARG FNETD_PASSWORD
ENV FNETD_PASSWORD $FNETD_PASSWORD

ARG RELEASE_PORT
ENV PORT_RELEASE $RELEASE_PORT

ARG DEBUG_PORT
ENV PORT_DEBUG $DEBUG_PORT

EXPOSE $DEBUG_PORT
EXPOSE $RELEASE_PORT

WORKDIR /home/pwn
RUN cp /home/pwn/source/activation_key.txt activation_key.txt


ENTRYPOINT ["sh", "-c", "fnetd -p $PORT_DEBUG -u pwn -lt 2 -lm 536870912 /home/pwn/debug/vuln & /fnetd/build/fnetd -p $PORT_RELEASE -u pwn -lt 2 -lm 536870912 /home/pwn/release/vuln"]
