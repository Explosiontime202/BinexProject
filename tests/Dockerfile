FROM debian:bullseye

RUN apt update -y && apt upgrade -y && apt install -y build-essential wget cmake screen

############### INSTALL FNETD
RUN wget https://cloud.sec.in.tum.de/index.php/s/n5cJnDqnnpSeEpd/download/fnetd.tar.xz -O /fnetd.tar.xz
RUN tar -xf fnetd.tar.xz
RUN mkdir /fnetd/build

WORKDIR /fnetd/build
RUN cmake .. -G "Unix Makefiles"
RUN make

WORKDIR /
############### END INSTALL

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
RUN cmake /home/pwn/source -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug
RUN make
RUN cp /home/pwn/source/activation_key.txt activation_key.txt

RUN mkdir /home/pwn/release
WORKDIR /home/pwn/release
RUN cmake /home/pwn/source -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
RUN make
RUN cp /home/pwn/source/activation_key.txt activation_key.txt

ARG FNETD_PASSWORD
ENV FNETD_PASSWORD $FNETD_PASSWORD

ARG RELEASE_PORT
ENV PORT_RELEASE $RELEASE_PORT

ARG DEBUG_PORT
ENV PORT_DEBUG $DEBUG_PORT

EXPOSE $PORT_DEBUG
EXPOSE $PORT_DEBUG

RUN screen -S release -dm bash -c "/fnetd/build/fnetd -p $RELEASE_PORT -u pwn -lt 2 -lm 536870912 /home/pwn/release/vuln; exec sh"
RUN screen -S debug -dm bash -c "/fnetd/build/fnetd -p $DEBUG_PORT -u pwn -lt 2 -lm 536870912 /home/pwn/debug/vuln; exec sh"

CMD ["/bin/bash"]
