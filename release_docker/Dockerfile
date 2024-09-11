FROM debian:bullseye


RUN apt update -y && apt upgrade -y && apt install -y build-essential wget cmake

COPY fnetd /bin/

COPY get_flag /bin/get_flag

COPY libc-2.31.so /lib/x86_64-linux-gnu/libc-2.31-bx.so
RUN ln -sf /lib/x86_64-linux-gnu/libc-2.31-bx.so /lib/x86_64-linux-gnu/libc.so.6

RUN useradd -m pwn

COPY vuln /home/pwn/vuln
COPY activation_key.txt /home/pwn/activation_key.txt

RUN chmod 0755 /home/pwn/vuln

EXPOSE 1337

# Feel free to replace password with the actual chall pw
ENV FNETD_PASSWORD=
CMD ["fnetd", "-p", "1337", "-u", "pwn", "-lt", "2", "-lm", "536870912", "./vuln"]
