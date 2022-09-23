#include <stdio.h>
#include "wiredtiger_internal.h"

int main() {
    printf("Printing size of specific structs to stub them in BPF!\n");
    WT_SPINLOCK spinlock;
    printf("BPF: size of WT_SPINLOCK: %lu\n", sizeof(spinlock));
    wt_mutex_t mutex;
    printf("BPF: size of wt_mutex_t: %lu\n", sizeof(mutex));
    wt_cond_t condition_var;
    printf("BPF: size of wt_cond_t: %lu\n", sizeof(condition_var));

    return 0;
}