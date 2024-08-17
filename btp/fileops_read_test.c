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
    if (pid == 0) {
        execl("/testcases/read01", "read01", NULL);
    }
    waitpid(pid, NULL, 0);
    pid = vfork();
    if (pid == 0) {
        execl("/testcases/read02", "read02", NULL);
    }
    waitpid(pid, NULL, 0);
    pid = vfork();
    if (pid == 0) {
        execl("/testcases/read03", "read03", NULL);
    }
    waitpid(pid, NULL, 0);
    pid = vfork();
    if (pid == 0) {
        execl("/testcases/read04", "read04", NULL);
    }
    waitpid(pid, NULL, 0);
}