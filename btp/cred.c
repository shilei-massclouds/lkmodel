#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <assert.h>

#define TEST_FILE   "test_file"

static int test_noatime()
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
    return 0;
}

static int test_open_for_write()
{
    int fd;
    struct passwd *ltpuser;
    char *user2_fname = "user2_0600";

    remove(user2_fname);

    fd = creat(user2_fname, 0600);
    if (creat(user2_fname, 0600) < 0) {
        perror("create user2_fname error");
        exit(-1);
    }
    close(fd);

    /* Switch to nobody user for correct error code collection */
    ltpuser = getpwnam("nobody");
    setgid(ltpuser->pw_gid);
    setuid(ltpuser->pw_uid);

    printf("expect error for (O_WRONLY) ...\n");
    fd = open(user2_fname, O_WRONLY, 0644);
    assert(fd == -1);

    return 0;
}

int main()
{
    printf("cred: test ..\n");

    test_noatime();
    test_open_for_write();

    printf("cred: test ok!\n");
    return 0;
}
