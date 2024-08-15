#include <stdio.h>
#include <stdlib.h>

int main()
{
    int ret = 0;
    const char *cmd = "grep abc opt/syscalls > /dev/null";
    printf("system(%s) ...\n", cmd);
    ret = system(cmd);
    printf("system(%s) ret: %d\n", cmd, ret);
    return 0;
}
