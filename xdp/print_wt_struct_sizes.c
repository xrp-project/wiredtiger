#include <stdio.h>
#include <stdlib.h>
#include <wiredtiger.h>

int main() {
    const char *data_dir = "/tigerhome/directio";
    const char *conn_config =
        "create,direct_io=[data,checkpoint],buffer_alignment=512B,mmap=false,"
        "cache_size=128M,"
        "eviction_trigger=95,eviction_target=80,eviction=(threads_max=2,"
        "threads_min=2),statistics=("
        "fast)";

    WT_CONNECTION *conn;

    int ret = wiredtiger_open(data_dir, NULL, conn_config, &conn);
    if (ret) {
        printf("Failed to open wiredtiger database\n");
        exit(1);
    }
    return 0;
}