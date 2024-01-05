#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PROGRAM_LEN 0x10000

typedef enum Instruction : uint8_t { TODO } Instruction;

Instruction *get_program(size_t *program_len) {
    puts("Now to your next program: How long should it bee?");

    size_t len;
    char len_buf[0x10];
    char *end_ptr;
    do {
        if (fgets(len_buf, sizeof(len_buf), stdin) == NULL) {
            exit(EXIT_FAILURE);
        }
        len = strtoull(len_buf, &end_ptr, 0);

        if (len_buf == end_ptr) {
            puts("That's not a integer, come back when you passed elementary school!");
            exit(EXIT_FAILURE);
        }

        if (len <= MAX_PROGRAM_LEN) {
            break;
        }

        puts("Nah, that's to long. Let's try again.");

    } while (true);

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

int run_jit(Instruction *program, size_t len) { return 0; }

int main() {
    // TODO: better pun, add reference to pop-culture
    puts("Welcome to JIT-aaS (Just In Time - always a Surprise)");

    Instruction *program;
    size_t program_len;
    int exit_code;

    while (true) {
        program = get_program(&program_len);

        exit_code = run_jit(program, program_len);

        printf("Your program exited with %d\n", exit_code);
        free(program);
    }
}
