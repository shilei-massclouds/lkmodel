#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <assert.h>

#define TEST_FILE   "test_file"

int main()
{
    int fd;
    struct passwd *ltpuser;

    remove(TEST_FILE);

    fd = creat(TEST_FILE, 0644);
    if (fd < 0) {
        perror("create file error");
        exit(-1);
    }
    close(fd);

    ltpuser = getpwnam("nobody");
    if (ltpuser == NULL) {
        perror("bad user");
        exit(-1);
    }

    printf("name %s, pwd %s, uid %u, gid %u\n",
           ltpuser->pw_name, ltpuser->pw_passwd,
           ltpuser->pw_uid, ltpuser->pw_gid);

    if (seteuid(ltpuser->pw_uid) < 0) {
        perror("bad euid");
        exit(-1);
    }

    printf("expect error for (O_RDONLY|O_NOATIME) ...\n");
    fd = open(TEST_FILE, O_RDONLY | O_NOATIME, 0444);
    assert(fd == -1);

    seteuid(0);

    printf("cred: test ok!\n");
    return 0;
}
