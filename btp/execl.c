#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
    printf("Hello, execl!\n");

    pid_t pid = vfork();
    if (pid == 0) {
        printf("Child is running ...\n");
        execl("/btp/sbin/hello", "init", NULL);
        exit(0);
    } else {
        int ret = 0;
        waitpid(pid, &ret, 0);
        printf("Parent gets code [%d]\n", ret);
    }
    return 0;
}
