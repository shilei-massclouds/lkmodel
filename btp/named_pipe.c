#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#define FIFO_NAME "/tmp/fifo_file"

int main()
{
    int rfd;
    int ret;

    if(access(FIFO_NAME, F_OK) == -1) {
        ret = mkfifo(FIFO_NAME, 0777);
        if (ret < 0) {
            perror("mkfifo error!");
            exit(-1);
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        int wfd;
        char buf[] = "hello, pipe!";

        printf("child is opening pipe .. \n");
        wfd = open(FIFO_NAME, O_WRONLY);
        if (wfd < 0) {
            perror("child opens pipe error!");
            exit(-1);
        }

        if (write(wfd, buf, sizeof(buf)) != sizeof(buf)) {
            perror("child writes to pipe error!");
            exit(-1);
        }

        printf("child writes to pipe ok!\n");
        close(wfd);
        printf("child prepares to exit..\n");
        exit(0);
    }

    printf("parent open ..\n");
    rfd = open(FIFO_NAME, O_RDONLY);
    if (rfd < 0) {
        perror("parent opens pipe error!");
        exit(-1);
    }

    char buf[32] = {0};
    read(rfd, buf, sizeof(buf));
    printf("parent reads [%s]\n", buf);

    close(rfd);

    printf("parent is waiting for child to exit ..\n");
    waitpid(pid, NULL, 0);

    printf("parent removes pipe file ..\n");
    ret = remove(FIFO_NAME);
    if (ret < 0) {
        perror("remove file error!");
        exit(-1);
    }

    printf("named pipe test ok!\n");
    return 0;
}
