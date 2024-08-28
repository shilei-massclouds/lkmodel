#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct results {
    int passed;
    int failed;
};

void test(const char *, struct results *);

int main()
{
    printf("Test syscalls ...\n");

    FILE *fp = fopen("/opt/syscalls", "r");

    struct results r = {0, 0};
    while (1) {
        char buf[64];
        if (fgets(buf, sizeof(buf), fp) == NULL) {
            break;
        }
        test(strtok(buf, "\n"), &r);
    }

    fclose(fp);

    printf("\n");
    printf("==========\n");
    printf("Passed: %d\n", r.passed);
    printf("Failed: %d\n", r.failed);
    printf("Total: %d\n", r.passed + r.failed);
    printf("==========\n");
    return 0;
}

void test(const char *name, struct results *r) {
    if (name == NULL || strlen(name) == 0)
        return;

    printf("[%s] ...\n", name);

    char buf[128];
    sprintf(buf, "/testcases/%s", name);

    pid_t pid = vfork();
    if (pid == 0) {
        execl(buf, name, NULL);
        exit(0);
    }

    int ret = 0;
    waitpid(pid, &ret, 0);
    if (ret == 0) {
        printf("[%s] ok!\n", name);
        r->passed++;
    } else if (ret == 4) {
        /* Passed with warnings */
        printf("[%s] ok with warings!\n", name);
        r->passed++;
    } else {
        printf("[%s] err [%d]!\n", name, ret);
        r->failed++;
    }
}
