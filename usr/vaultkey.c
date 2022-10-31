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
#include <openssl/md5.h>

#define NL_PASSWD 25
#define MD5_SIZE 16
#define MAX_PAYLOAD 1024
#define PASSWD_MD5 "e10adc3949ba59abbe56e057f20f883"
#define TRUE 1

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

void set_auth_flag_true(void) {
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
	strcpy(NLMSG_DATA(nlh), "");
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

int main(int argc, char *argv[]) {
	char *passwd = malloc(sizeof(char *)), *passwd_md5 = malloc(sizeof(char *));
	int count = 0;
	printf("Please input your password.\n");
	while (TRUE) {
		system("stty -echo");
		scanf("%s", passwd);
		system("stty echo");
		md5_calc(passwd, passwd_md5);
		if (strncmp(passwd_md5, PASSWD_MD5, strlen(PASSWD_MD5)) == 0) {
			set_auth_flag_true();
			printf("Welcome to basic file vault!\n");
			break;
		} else {
			count++;
			if (count >= 5) {
				printf("Too many errors!\n");
				break;
			}
			printf("Wrong password! Please try again!\n");
		}
	}
	return 0;
}
