#include <stdio.h>
#include <stdlib.h>

unsigned long ax_sqrt(unsigned long n)
{
    unsigned long x = n;
    while (1) {
        if (x * x <= n && (x + 1) * (x + 1) > n) {
            return x;
        }
        x = (x + n / x) / 2;
    }
}

int main()
{
    int i;
    int seed;
    for (i = 0; i < 1000000; i++) {
        // Only for consuming time.
        seed += ax_sqrt(1048577+i);
    }
    unsigned long ret = ax_sqrt(seed);
    printf("Hello, Init! Sqrt(1048577) = %lu \n", ret);
    return 0;
}
