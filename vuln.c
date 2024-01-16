#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PROGRAM_LEN 0x1000

typedef enum Opcode { ADD = 0, ADDI = 1, SUB = 2, COPY = 3, LOADI = 4, COUNT_OPCODES } Opcode;

typedef enum Register {
    Adelheid = 0,
    Berthold = 1,
    Cornelia = 2,
    Dora = 3,
    Engelbert = 4,
    Friedrich = 5,
    Giesela = 6,
    Heinrich = 7,
    I = 8,
    J = 9,
    K = 10,
    L = 11,
    M = 12,
    N = 13,
    COUNT_REGISTERS
} Register;

typedef struct Instruction {
    Opcode opcode;
    Register reg1;
    uint8_t padding[2]; // unused
    union {
        Register reg2;
        uint32_t imm;
    };
} Instruction;

typedef int (*exec_func_t)();

static __attribute__((unused)) bool premium_activated = false;

// Take a look at https://wiki.osdev.org/X86-64_Instruction_Encoding#Registers for more information.
static uint8_t register_id_lookup[COUNT_REGISTERS] = {
    0b0000, // A is mapped to rax
    0b0011, // B to rbx
    0b0001, // C to rcx
    0b0010, // D to rdx
    0b0110, // E to rsi
    0b0111, // F to rdi
    0b1000, // G to r8
    0b1001, // H to r9
    0b1010, // I to r10
    0b1011, // J to r11
    0b1100, // K to r12
    0b1101, // L to r13
    0b1110, // M to r14
    0b1111, // N to r15
};

#define EXTRACT_REX_BIT(x) ((x >> 3) & 1)

size_t get_size_t(size_t min, size_t limit) {
    size_t val;
    char buf[0x10] = {0};
    char *end_ptr;
    do {
        if (fgets(buf, sizeof(buf), stdin) == NULL)
            exit(EXIT_FAILURE);

        val = strtoull(buf, &end_ptr, 0);

        if (buf == end_ptr) {
            puts("That's not a integer, come back when you passed elementary school!");
            exit(EXIT_FAILURE);
        }

        if (val <= limit && val >= min)
            break;

        puts("Nah, that's too long. Let's try again.");
    } while (true);
    return val;
}

Instruction *get_program(size_t *program_len) {
    printf("Now to your next program: How long should it bee?");
    size_t len = get_size_t(1, MAX_PROGRAM_LEN);

    Instruction *program = malloc(len * sizeof(Instruction));

    if (program == NULL) {
        puts("Cannot malloc anything!");
        exit(EXIT_FAILURE);
    }

    printf("Now your program:");

    if (fread(program, sizeof(Instruction), len, stdin) != len) {
        puts("You did not enter as many instructions as you wanted. Learn counting, idiot!");
        free(program);
        exit(EXIT_FAILURE);
    }

    *program_len = len;
    return program;
}

bool instr_use_reg2(Opcode opcode) { return opcode == ADD || opcode == SUB || opcode == COPY; }

bool validate_program(Instruction *program, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // prevent use of wrong opcodes or registers
        if (program[i].opcode >= COUNT_OPCODES || program[i].reg1 >= COUNT_REGISTERS)
            return false;

        if (instr_use_reg2(program[i].opcode) && program[i].reg2 >= COUNT_REGISTERS)
            return false;
    }
    return true;
}

void init_seccomp() {
    // TODO:
}

void exec_code(uint8_t *code) {
    exec_func_t exec_func = (exec_func_t)code;
    close(0);
    close(1);
    close(2);
    init_seccomp();
    uint8_t res = exec_func();
    _exit(res);
}

void gen_3B_native_instr(uint8_t opcode, uint8_t reg1_id, uint8_t reg2_id, uint8_t *code, size_t *offset) {
    // REW.X prefix (we use 64bit registers) + upper bit of the second register id + upper bit of the first register id
    code[*offset] = 0b01001000 + (EXTRACT_REX_BIT(reg2_id) << 2) + EXTRACT_REX_BIT(reg1_id);
    code[*offset + 1] = opcode;
    // registers: direct addressing + second reg id + first reg id
    code[*offset + 2] = 0b11000000 + (reg2_id << 3) + reg1_id;
    *offset += 3;
}

void gen_immediate_native_instr(uint8_t opcode, uint8_t reg_id, uint32_t imm, uint8_t *code, size_t *offset) {
    code[*offset] = 0b01001000 + EXTRACT_REX_BIT(reg_id); // REW.X prefix (we use 64bit registers) + upper bit of the first register id
    code[*offset + 1] = opcode;
    code[*offset + 2] = 0b11000000L + (reg_id & 0b111); // registers: direct addressing + lower 3 bit of first reg id
    *(uint32_t *)(code + *offset + 3) = imm;            // immediate
    *offset += 7;
}

void gen_code(uint8_t *code, Instruction *program, size_t program_len) {
    // guides on how x64 instructions are encoded:
    // https://wiki.osdev.org/X86-64_Instruction_Encoding
    // https://pyokagan.name/blog/2019-09-20-x86encoding/

    size_t offset = 0;
    uint32_t acc = 0;
    uint8_t reg1_id;
    uint8_t reg2_id;

    // prolog: zero out registers
    for (Register reg = Adelheid; reg < COUNT_REGISTERS; ++reg) {
        // mov reg, 0
        gen_immediate_native_instr(0xc7, register_id_lookup[reg], 0, code, &offset);
    }

    for (size_t pc = 0; pc < program_len; ++pc) {
        Instruction instr = program[pc];
        switch (instr.opcode) {
        case ADD:
            // add reg1, reg2
            gen_3B_native_instr(0x01, register_id_lookup[instr.reg1], register_id_lookup[instr.reg2], code, &offset);
            break;
        case ADDI:
            // optimization: fold multiple consecutive ADDI instructions to the same register into one
            if (pc < program_len && program[pc + 1].opcode == ADDI && instr.reg1 == program[pc + 1].reg1) {
                acc += program[pc].imm;
            } else {
                // add reg, acc
                gen_immediate_native_instr(0x81, register_id_lookup[instr.reg1], instr.imm + acc, code, &offset);
                acc = 0;
            }
            break;
        case SUB:
            // add reg1, reg2
            gen_3B_native_instr(0x29, register_id_lookup[instr.reg1], register_id_lookup[instr.reg2], code, &offset);
            break;
        case COPY:
            // optimization: COPY from and to a register is a nop
            reg1_id = register_id_lookup[instr.reg1];
            reg2_id = register_id_lookup[instr.reg2];
            if (reg1_id == reg2_id)
                break;

            // mov reg1, reg2
            gen_3B_native_instr(0x89, reg1_id, reg2_id, code, &offset);
            break;
        case LOADI:
            // optimization: multiple consecutive loads to the same register are unnecessary
            if (pc < program_len && program[pc + 1].opcode == LOADI && instr.reg1 == program[pc + 1].reg1)
                break;

            gen_immediate_native_instr(0xc7, register_id_lookup[instr.reg1], instr.imm, code, &offset);
            break;
        default:
            puts("Found invalid instruction!");
            exit(EXIT_FAILURE);
        }
    }

    // epilog: return lower 8bit of Adelheid as return value
    // mov rdi, Adelheid
    gen_3B_native_instr(0x89, 0b0111, register_id_lookup[Adelheid], code, &offset);
    // ret
    code[offset] = 0xc3;
}

uint8_t run_jit(Instruction *program, size_t len) {
    // an instruction takes up to 7B + prolog + epilog
    size_t expected_code_len = 7 * len + 3 * COUNT_REGISTERS + 4;
    // page alignment
    size_t allocated_code_len = (expected_code_len + 0xFFF) & ~0xFFF;

    // TODO: maybe randomly choose address to make exploitation harder
    // allocate memory for context and code
    uint8_t *code = (uint8_t *)mmap(NULL, allocated_code_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == (void *)-1) {
        puts("Cannot mmap memory for code.");
        exit(EXIT_FAILURE);
    }
    gen_code(code, program, len);

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

    return WEXITSTATUS(wstatus);
}

int main() {
    // TODO: signal handlers? SIGCHILD? seccomp?
    // TODO: colors in message, just so that everyone is pissed :D

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

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

        printf("Your program exited with %d!\n", exit_code);
        free(program);
    }
}
