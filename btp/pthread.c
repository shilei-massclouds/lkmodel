#include <stdio.h>
#include <pthread.h>

static void *func(void *limit)
{
    printf("child func ...\n");
    return NULL;
}

int main()
{
    pthread_t t;
    printf("pthread ...\n");
    pthread_create(&t, NULL, func, NULL);
    pthread_join(t, NULL);
    printf("pthread ok!\n");
    return 0;
}
