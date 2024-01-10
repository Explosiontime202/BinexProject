#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PROGRAM_LEN 0x1000

typedef enum Opcode : uint8_t { ADD = 1, SHIFT = 2, MOV = 3, COUNT_OPCODES } Opcode;

typedef enum Register : uint8_t { A = 0, B = 1, C = 2, D = 3, E = 4, F = 5, COUNT_REGISTERS } Register;

typedef struct Instruction {
    Opcode opcode;
    Register reg;
} Instruction;

typedef int (*exec_func_t)();

static __attribute__((unused)) bool premium_activated = false;

size_t get_size_t(size_t limit) {
    size_t val;
    char buf[0x10];
    char *end_ptr;
    do {
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            exit(EXIT_FAILURE);
        }
        val = strtoull(buf, &end_ptr, 0);

        if (buf == end_ptr) {
            puts("That's not a integer, come back when you passed elementary school!");
            exit(EXIT_FAILURE);
        }

        if (val <= limit) {
            break;
        }

        puts("Nah, that's to long. Let's try again.");
    } while (true);
    return val;
}

Instruction *get_program(size_t *program_len) {
    puts("Now to your next program: How long should it bee?");
    size_t len = get_size_t(MAX_PROGRAM_LEN);

    Instruction *program = malloc(len * sizeof(Instruction));

    if (program == NULL) {
        exit(EXIT_FAILURE);
    }

    if (fread(program, sizeof(Instruction), len, stdin) != len) {
        puts("You did not enter as many instructions as you wanted. Learn counting, idiot!");
        free(program);
        exit(EXIT_FAILURE);
    }

    *program_len = len;
    return program;
}

bool validate_program(Instruction *program, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // prevent use of wrong opcodes or registers
        if (program[i].opcode >= COUNT_OPCODES || program[i].reg >= COUNT_REGISTERS) {
            return false;
        }
    }
    return true;
}

void init_seccomp() {
    // TODO:
}

void exec_code(uint8_t *code) {
    exec_func_t exec_func = (exec_func_t)code;
    init_seccomp();
    close(0);
    close(1);
    close(2);
    uint8_t res = exec_func();
    _exit(res);
}

void write_instr(uint8_t *code, size_t offset, const uint8_t *instr, size_t instr_len) {
    for (size_t i = 0; i < instr_len; ++i) {
        code[offset + i] = instr[i];
    }
}

void gen_code(uint8_t *code, Instruction *program, size_t program_len) {
    Register cur_reg;
    size_t acc;
    for (size_t pc = 0; pc < program_len; ++pc) {
        switch (program[pc].opcode) {
        case ADD:
            if (program[pc].reg == cur_reg) {

            }
        default:
            puts("Found invalid instruction!");
            exit(EXIT_FAILURE);
        }
    }
}

int run_jit(Instruction *program, size_t len) {
    // TODO:
    size_t expected_code_len = 0;
    // page alignment
    size_t allocated_code_len = (expected_code_len + 0xFFF) & ~0xFFF;

    // allocate memory for context and code
    uint8_t *code = (uint8_t *)mmap(NULL, allocated_code_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == (void *)-1) {
        puts("Cannot mmap memory for code.");
        exit(EXIT_FAILURE);
    }
    gen_code(code, program);

    // make code executable and non-writeable
    if (mprotect(code, allocated_code_len, PROT_READ | PROT_EXEC) != 0) {
        puts("Cannot make code executable!");
        exit(EXIT_FAILURE);
    }

    int child_pid = fork();
    switch (child_pid) {
    case -1:
        puts("I'm infertile, I cannot have a child \U0001F62D");
        exit(EXIT_FAILURE);
    case 0:
        // child
        exec_code(code);
        __builtin_unreachable();
    default:
        // parent
        break;
    }

    // continue in the parent; child never gets here

    // unmap allocated memory
    if (munmap(code, allocated_code_len) != 0) {
        puts("Cannot unmap code.");
        exit(EXIT_FAILURE);
    }

    // wait for child and extract exit code
    int wstatus = 0;
    if (waitpid(child_pid, &wstatus, 0) == -1) {
        puts("waitpid failed!");
        exit(EXIT_FAILURE);
    }

    if (!WIFEXITED(wstatus)) {
        puts("Program crashed! WHAT?");
        exit(EXIT_FAILURE);
    }

    uint8_t exit_code = WEXITSTATUS(wstatus);

    return exit_code;
}

int main() {
    // TODO: signal handlers? SIGCHILD? seccomp?

    // TODO: better pun, add reference to pop-culture
    puts("Welcome to JIT-aaS (Just In Time - always a Surprise)");

    Instruction *program;
    size_t program_len;
    int exit_code;

    while (true) {
        // TODO: check for password and enable premium mode
        program = get_program(&program_len);
        if (!validate_program(program, program_len)) {
            puts("Your program is not valid. You possibly use invalid opcodes or registers!");
            free(program);
            continue;
        }

        exit_code = run_jit(program, program_len);

        printf("Your program exited with %d\n", exit_code);
        free(program);
    }
}
