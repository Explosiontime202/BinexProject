FROM debian:bullseye


RUN apt update -y && apt upgrade -y && apt install -y build-essential wget cmake


############### INSTALL FNETD
RUN wget https://cloud.sec.in.tum.de/index.php/s/n5cJnDqnnpSeEpd/download/fnetd.tar.xz -O /fnetd.tar.xz
RUN tar -xf fnetd.tar.xz
RUN mkdir /fnetd/build

WORKDIR /fnetd/build
RUN cmake .. -G "Unix Makefiles"
RUN make

WORKDIR /
############### END INSTALL

## Add your own dummy get_flag here
# COPY get_flag /bin/get_flag

## Uncomment to use course libc.
# COPY libc-2.31.so /lib/x86_64-linux-gnu/libc-2.31-bx.so
# RUN ln -sf /lib/x86_64-linux-gnu/libc-2.31-bx.so /lib/x86_64-linux-gnu/libc.so.6

RUN useradd -m pwn

COPY vuln /home/pwn/vuln
COPY activation_key.txt /home/pwn/activation_key.txt

RUN chmod 0755 /home/pwn/vuln

EXPOSE 1337

# Feel free to replace password with the actual chall pw
ENV FNETD_PASSWORD=
CMD ["/fnetd/build/fnetd", "-p", "1337", "-u", "pwn", "-lt", "2", "-lm", "536870912", "./vuln"]
