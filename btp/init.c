#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 1024

// 拼接路径与文件名
char* path_concate(size_t path_len,const char * path,const char *file_name) {
    char *full_path = malloc(path_len + strlen(file_name) + 2);
    strncpy(full_path, path, path_len);
    full_path[path_len] = '/';
    strncat(full_path, file_name, strlen(file_name));
    full_path[path_len + strlen(file_name) + 1] = '\0';
    return full_path;
}

// 判断字符串是否是路径
bool isLikelyPath(const char *str) {
    // 检查是否以斜杠开头,斜杠,点
    if (str[0] == '/' || strchr(str, '/') != NULL || strchr(str, '.') != NULL) {
        return true;
    }
    return false;
}

// 运行一个脚本
int run_one_script(const char *script_path) {
    const char* sbin_path = "/sbin";
    FILE *script;
    char buffer[BUFFER_SIZE];
    char *args[10]; // 假设每行最多有9个参数加上NULL指针
    int arg_count; // 参数个数
    // 打开脚本文件
    script = fopen(script_path, "r");
    
    if (script == NULL) {
        perror("Error opening script file");
        return 1;
    }

    // 逐行读取脚本文件
    while (fgets(buffer, BUFFER_SIZE, script) != NULL) {
        // 将换行符转换为\0
        buffer[strcspn(buffer, "\n")] = '\0';
        // 解析行中的参数
        arg_count = 0;
        char *token = strtok(buffer, " \t"); // 使用空格和制表符作为分隔符
        while (token != NULL && arg_count < 9) { // 最多支持9个参数
            args[arg_count++] = token;
            token = strtok(NULL, " \t");
        }
        args[arg_count] = NULL; // 确保参数列表以NULL结束

        // 使用execl执行命令
        if (arg_count > 0) {
            if (!isLikelyPath(args[0])) {
                char *excute_path = path_concate(strlen(sbin_path),sbin_path,args[0]);
                pid_t pid = vfork();
                if (pid == 0) {
                    execl(excute_path, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], NULL);
                    exit(0);
                }
                free(excute_path);
                waitpid(pid, NULL, 0);
            }else{
                pid_t pid = vfork();
                if (pid == 0) {
                    execl(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], NULL);
                }
                waitpid(pid, NULL, 0);
            }
        }

        // 重置参数计数器，为下一行做准备
        arg_count = 0;
    }

    // 关闭脚本文件
    fclose(script);
}

// 运行path脚本 
// TODO: 按照linux那样按照文件命名运行脚本,lkmodel读取目录这边好像存在问题。
void run_scripts(const char *path) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    size_t path_len = strlen(path);

    if ((dir = opendir(path)) == NULL) {
        perror("opendir");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char* script_path = path_concate(path_len,path,entry->d_name);
        if (run_one_script(script_path) != 0) {
            fprintf(stderr,"script %s run error",script_path);
        }
        free(script_path);
    }
    closedir(dir);
}
int main(int argc, char *argv[])
{
    printf("Hello, init!\n");
    // run_scripts("/etc/init.d");
    run_one_script("/etc/init.d/rcS");

    return 0;
}