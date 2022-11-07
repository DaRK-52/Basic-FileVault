#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#include <dirent.h>
#include <openssl/md5.h>

#define NL_PASSWD 25
#define MD5_SIZE 16
#define MAX_PAYLOAD 1024
#define PASSWD_MD5_PATH "/.passwd.md5"
#define VP_FILE_PATH "/home/zhuwenjun/.vault.path"
#define MSG_AUTH_FLAG_TRUE "true"
#define COMMAND_HELP "h"
#define COMMAND_PASSWD "p"
#define COMMAND_CP "cp"
#define COMMAND_CVP "cvp"
#define COMMAND_EXIT "exit"
#define SLASH "/"
#define MAX_LENGTH 64
#define TRUE 1

char *correct_passwd_md5;
char *passwd_file_path;
FILE *passwd_file;
FILE *vp_file;

void md5_calc(char *passwd, char *dst_str) {
	MD5_CTX md5;
	unsigned char md5_value[MD5_SIZE];

	MD5_Init(&md5);
	MD5_Update(&md5, passwd, strlen(passwd));
	MD5_Final(md5_value, &md5);

	for (int i = 0;i < MD5_SIZE;i++) {
		sprintf(dst_str + i*2, "%02x", md5_value[i]);
	}
	return;
}

void send_msg_to_kernel(char *msg_str) {
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct msghdr msg;
	struct iovec iov;
	int sockfd;
	
	sockfd = socket(AF_NETLINK, SOCK_RAW, NL_PASSWD);
	memset(&src_addr, 0, sizeof(src_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&msg, 0, sizeof(msg));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = 100;
	src_addr.nl_groups = 0;
	bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr));
	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_pid = 100;
	nlh->nlmsg_flags = 0;
	strcpy(NLMSG_DATA(nlh), msg_str);
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	sendmsg(sockfd, &msg, 0);
	close(sockfd);
	return;
}

void set_auth_flag_true(void) {
	send_msg_to_kernel(MSG_AUTH_FLAG_TRUE);
}

void print_help() {
	char buf[255];
	FILE *help_file;
	help_file = fopen("help.txt", "r");
	while(fgets(buf, MAX_LENGTH, help_file) != NULL) {
		printf("%s", buf);
	}
	printf("\n");
	fclose(help_file);
}

void get_correct_passwd_md5() {
	passwd_file_path = malloc(sizeof(char *) * MAX_LENGTH);
	correct_passwd_md5 = malloc(sizeof(char *) * 2 * MD5_SIZE);
	vp_file = fopen(VP_FILE_PATH, "r");
	fscanf(vp_file, "%s", passwd_file_path);
	strcat(passwd_file_path, PASSWD_MD5_PATH);
	passwd_file = fopen(passwd_file_path, "r");
	fscanf(passwd_file, "%s", correct_passwd_md5);
	fclose(vp_file);
	fclose(passwd_file);
}

int input_passwd() {
	char *passwd = malloc(sizeof(char *) * MAX_LENGTH), *passwd_md5 = malloc(sizeof(char *) * MAX_LENGTH);
	int count = 0;

	while (TRUE) {
		printf("Please input your password!\n");
		system("stty -echo");
		scanf("%s", passwd);
		system("stty echo");
		md5_calc(passwd, passwd_md5);
		if (strncmp(passwd_md5, correct_passwd_md5, strlen(correct_passwd_md5)) == 0) {
			set_auth_flag_true();
			printf("Welcome to basic file vault!\n");
			return 1;
		} else {
			count++;
			if (count >= 5) {
				printf("Too many errors!\n");
				return 0;
			}
			printf("Wrong password! Please try again!\n");
		}
	}
	free(passwd);
	free(passwd_md5);
}

void change_passwd() {
	char *new_passwd1 = malloc(sizeof(char *) * MAX_LENGTH),
		*new_passwd2 = malloc(sizeof(char *) * MAX_LENGTH),
		*new_passwd_md5 = malloc(sizeof(char *) * MAX_LENGTH);
	passwd_file = fopen(passwd_file_path, "w");
	printf("Please input new password!\n");
	system("stty -echo");
	scanf("%s", new_passwd1);
	printf("Please input new passwd again!\n");
	scanf("%s", new_passwd2);
	system("stty echo");
	if (strcmp(new_passwd1, new_passwd2) != 0) {
		printf("Error! Entered passwords differ!\n");
	}
	md5_calc(new_passwd1, new_passwd_md5);
	fprintf(passwd_file, "%s", new_passwd_md5);
	printf("Password is changed successfully!\n");
	correct_passwd_md5 = new_passwd_md5;
	free(new_passwd1);
	free(new_passwd2);
	fclose(passwd_file);
}

char *strip_end_slash(char *s) {
	int length = strlen(s);
	char *tmp = malloc(sizeof(char *) * MAX_LENGTH);
	
	if (length <= 0 || strcmp(s + length - 1, SLASH) != 0)
		return s;
	for (int i = length; i > 0; i--) {
		if (strncmp(s + i - 1, SLASH, strlen(SLASH)) != 0) {
			strncpy(tmp, s, i);
			break;
		}
	}
	return tmp;
}

/*
	Set vault path in the file ~/.vault.path
*/
void set_vault_path(char *new_vault_path) {
	vp_file = fopen(VP_FILE_PATH, "w");
	fprintf(vp_file, "%s", new_vault_path);
	fclose(vp_file);
}

/*
	This function exists some potential security problems
	like injecting, but it doesn't matter. ^_^
*/
void change_vault_path() {
	char *new_vault_path = malloc(sizeof(char *) * MAX_LENGTH);
	DIR* dir;

	printf("Please input new vault path!\n");
	scanf("%s", new_vault_path);
	new_vault_path = strip_end_slash(new_vault_path);
	dir = opendir(new_vault_path);
	if (dir) {
		send_msg_to_kernel(new_vault_path);
		set_vault_path(new_vault_path);
		printf("Change vault path successfully!\n");
	} else if (errno == ENOENT) {
		if(mkdir(new_vault_path, 0777) == -1) {
			printf("Failed to create new directory: %s\n", new_vault_path);
		} else {
			send_msg_to_kernel(new_vault_path);
			set_vault_path(new_vault_path);
			printf("Create directory %s and change vault path successfully!\n", new_vault_path);
		}
	} else {
		printf("Invalid path or other problems!\n");
	}
}

void just_for_test(int argc) {
	if (argc > 1) {
		set_auth_flag_true();
		exit(0);
	}
}

int main(int argc, char *argv[]) {
	char *cmd = malloc(sizeof(char *) * MAX_LENGTH);

	just_for_test(argc);

	print_help();
	printf("Error: %s\n", strerror(errno));
	get_correct_passwd_md5();
	
	while (TRUE) {
		printf("> ");
		scanf("%s", cmd);
		if (strcmp(cmd, COMMAND_HELP) == 0){
			print_help();
		} else if (strcmp(cmd, COMMAND_PASSWD) == 0) {
			if (input_passwd())
				break;
		} else if (strcmp(cmd, COMMAND_CP) == 0) {
			change_passwd();
		} else if (strcmp(cmd, COMMAND_CVP) == 0) {
			change_vault_path();
		} else if (strcmp(cmd, COMMAND_EXIT) == 0) {
			break;
		} else {
			printf("Unkown commands!\n");
		}
	}
	free(cmd);
	free(correct_passwd_md5);
	free(passwd_file_path);
	return 0;
}
