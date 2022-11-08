#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main() {
    // fd = open(file_path, O_RDONLY);
    // dir = opendir(dir_path);
    printf("%s\n", getenv("HOME"));
	// closedir(dir);
    // close(fd);
    return 0;
}
