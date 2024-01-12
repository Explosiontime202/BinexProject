#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int init_seccomp() {
#define ALLOW(NR) BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (NR), 0, 1), BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),

        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        ALLOW(SYS_read),
        ALLOW(SYS_exit_group),
        ALLOW(SYS_write),
        ALLOW(SYS_execve),

        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    };
#undef ALLOW

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(*filter),
        .filter = filter,
    };

    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

void *thread_f(void *arg) {
    init_seccomp();

    printf("Thread\n");
//    execve("./get_flag", NULL, NULL);

    return NULL;
}

int main() {
    pthread_t thread;

    printf("Starting up\n");

    // Create a thread
    if (pthread_create(&thread, NULL, thread_f, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    // Your main program logic here

    // Wait for the thread to finish
    if (pthread_join(thread, NULL) != 0) {
        perror("pthread_join");
        return 1;
    }

    printf("Main\n");
    execve("./get_flag", NULL, NULL);

    return 0;
}