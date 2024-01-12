#! /usr/bin/env python3

from pwn import *
from enum import IntEnum


class Opcode(IntEnum):
    ADD = 0
    ADDI = 1
    SUB = 2
    COPY = 3
    LOADI = 4


class Register(IntEnum):
    A = 0
    B = 1
    C = 2
    D = 3
    E = 4
    F = 5
    G = 6
    H = 7


INSTR_LEN = 8


def instr_i(opcode: Opcode, reg1: Register, imm: int):
    assert (opcode == Opcode.ADDI or opcode == Opcode.LOADI)
    assert (imm < 2 ** 32)
    return bytes([opcode, reg1, 0, 0]) + imm.to_bytes(4, byteorder='little')


def instr_r(opcode, reg1, reg2):
    assert (opcode == Opcode.ADD or opcode == Opcode.SUB or opcode == Opcode.COPY)
    return bytes([opcode, reg1, 0, 0, reg2, 0, 0, 0])


def exec_program(program: bytes) -> int | None:
    with remote("localhost", 1337, fam="ipv4") as p:
        p.recvuntil(b"Password: ", timeout=1)
        p.sendline(b"1234")

        msg = p.recvuntil(b"always a Surprise)", timeout=1)
        if msg == b'':
            return None
        print(msg.decode())

        msg = p.recvuntil(b"should it bee?", timeout=1)
        if msg == b'':
            return None
        print(msg.decode())

        len_msg = str(len(program) // INSTR_LEN).encode()
        log.info(f"Sending: {len_msg}")
        p.sendline(len_msg)

        msg = p.recvuntil(b"Now your program:", timeout=1)
        if msg == b'':
            return None
        print(msg.decode())

        log.info(f"Sending program: {list(program)}")
        p.send(program)

        msg = p.recvuntil(b"Your program exited with ", timeout=1)
        if msg == b'':
            return None
        print(msg.decode())

        exit_code = int(p.recvuntil(b"!", drop=True, timeout=1))
        return exit_code
