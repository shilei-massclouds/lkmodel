#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main()
{
   int pipefd[2];
   pid_t cpid;
   char buf;
   char input[] = "hello, pipe2!";

   if (pipe(pipefd) == -1) {
       perror("pipe");
       exit(EXIT_FAILURE);
   }
   printf("pipefd: %d, %d\n", pipefd[0], pipefd[1]);

   cpid = fork();
   if (cpid == -1) {
       perror("fork");
       exit(EXIT_FAILURE);
   }

   if (cpid == 0) {    /* Child reads from pipe */
       close(pipefd[1]);          /* Close unused write end */

       while (read(pipefd[0], &buf, 1) > 0)
           write(STDOUT_FILENO, &buf, 1);

       write(STDOUT_FILENO, "\n", 1);
       printf("child prepares to close ..\n");
       close(pipefd[0]);
       _exit(EXIT_SUCCESS);

   } else {            /* Parent writes argv[1] to pipe */
       close(pipefd[0]);          /* Close unused read end */
       write(pipefd[1], input, strlen(input));
       close(pipefd[1]);          /* Reader will see EOF */
       printf("parent is waitting for child to exit ..\n");
       wait(NULL);                /* Wait for child */
       printf("parent prepares to exit ..\n");
       exit(EXIT_SUCCESS);
   }
}
