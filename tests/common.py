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
    I = 8
    J = 9
    K = 10
    L = 11
    M = 12
    N = 13


INSTR_LEN = 8


def instr_i(opcode: Opcode, reg1: Register, imm: int):
    assert (opcode == Opcode.ADDI or opcode == Opcode.LOADI)
    assert (imm < 2 ** 32)
    return bytes([opcode, reg1, 0, 0]) + imm.to_bytes(4, byteorder='little')


def instr_r(opcode, reg1, reg2):
    assert (opcode == Opcode.ADD or opcode == Opcode.SUB or opcode == Opcode.COPY)
    return bytes([opcode, reg1, 0, 0, reg2, 0, 0, 0])


def exec_program(program: bytes, assert_f, debug: bool = False) -> int | None:
    if debug:
        context.log_level = 'debug'
    else:
        context.log_level = 'warn'

    with remote("localhost", 1337, fam="ipv4") as p:
        msg = p.recvuntil(b"Password: ", timeout=1)
        assert_f(msg != b'')
        p.sendline(b"1234")

        msg = p.recvuntil(b"COPaaS - Compiler-oriented programming as a service\n", timeout=1)
        assert_f(msg == b'COPaaS - Compiler-oriented programming as a service\n')

        msg = p.recvuntil(b"? (y/N):", timeout=1)
        assert_f(msg == b'Do you want to activate the premium version? (y/N):')

        p.sendline(b"N")
        msg = p.recvuntil(b"Using the demo version!\n")
        assert_f(msg == b"Using the demo version!\n")

        msg = p.recvuntil(b"should it bee?", timeout=1)
        assert_f(msg == b'Now to your next program: How long should it bee?')

        len_msg = str(len(program) // INSTR_LEN).encode()
        log.debug(f"Sending: {len_msg}")
        p.sendline(len_msg)

        msg = p.recvuntil(b"Now your program:", timeout=1)
        assert_f(msg == b'Now your program:')

        log.debug(f"Sending program: {list(program)}")
        p.send(program)

        msg = p.recvuntil(b"Your program exited with ", timeout=1)
        assert_f(msg == b'Your program exited with ')

        exit_code_msg = p.recvuntil(b"!", drop=True, timeout=1)
        assert_f(exit_code_msg != b'')

        exit_code = int(exit_code_msg)
        return exit_code
