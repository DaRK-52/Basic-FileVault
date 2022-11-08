#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>

int main() {
    // fd = open(file_path, O_RDONLY);
    // dir = opendir(dir_path);
	printf("%s\n", getpwuid(getuid())->pw_dir);
    // closedir(dir);
    // close(fd);
    return 0;
}
