#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

int main() {
    char *file_path = "/home/zhuwenjun/secret/flag";
    char *dir_path = "/home/zhuwenjun/secret";
    int fd;
    DIR *dir;
    fd = open(file_path, O_RDONLY);
    dir = opendir(dir_path);
    closedir(dir);
    close(fd);
    return 0;
}