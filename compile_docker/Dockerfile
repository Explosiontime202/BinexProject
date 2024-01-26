FROM debian:bullseye

#############################################
############ FOR COMPILING ONLY! ############
#############################################


RUN apt update -y && apt upgrade -y && apt install -y build-essential cmake

COPY libc-2.31.so /lib/x86_64-linux-gnu/libc-2.31-bx.so
RUN ln -sf /lib/x86_64-linux-gnu/libc-2.31-bx.so /lib/x86_64-linux-gnu/libc.so.6

RUN useradd -m pwn

# compile vuln
COPY parent.tar.xz /home/pwn/parent.tar.xz
RUN mkdir /home/pwn/source
RUN tar xvf /home/pwn/parent.tar.xz -C /home/pwn/source
RUN mkdir /home/pwn/build
WORKDIR /home/pwn/build
RUN cmake /home/pwn/source -G "Unix Makefiles"
RUN make

