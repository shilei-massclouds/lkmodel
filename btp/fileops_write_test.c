#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

void mount_fs() {
    pid_t pid = vfork();
    if (pid == 0) {
        execl("/btp/sbin/mount", "mount", "-a", NULL);
    }
    waitpid(pid, NULL, 0);
}

int main(){
    mount_fs();
    printf("fs mount done\n");
    pid_t pid = vfork();
    // if (pid == 0) {
    //     execl("/testcases/write01", "write01", NULL);
    // }
    // waitpid(pid, NULL, 0);
    // pid = vfork();
    if (pid == 0) {
        execl("/testcases/write02", "write02", NULL);
    }
    waitpid(pid, NULL, 0);
    pid = vfork();
    if (pid == 0) {
        execl("/testcases/write03", "write03", NULL);
    }
    waitpid(pid, NULL, 0);
    pid = vfork();
    if (pid == 0) {
        execl("/testcases/write04", "write04", NULL);
    }
    waitpid(pid, NULL, 0);
    pid = vfork();
    if (pid == 0) {
        execl("/testcases/write05", "write05", NULL);
    }
    waitpid(pid, NULL, 0);
}