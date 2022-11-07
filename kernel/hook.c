#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h> 
#include <linux/rtc.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs_struct.h>
#include <linux/limits.h> 
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/timer.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/mount.h>
#include <linux/namei.h>

#define VAULT_PATH "/home/zhuwenjun/secret"
#define SLASH "/"
#define SECRET "secret"
#define MAX_LENGTH 256
#define PERMITTED 1
#define UNPERMITTED 0

typedef asmlinkage long (*sys_call_fp)(struct pt_regs *regs);

unsigned short auth_flag = 0;

sys_call_fp old_openat = NULL;
sys_call_fp old_chdir = NULL;
sys_call_fp old_rename = NULL;
sys_call_fp old_unlinkat = NULL;
sys_call_fp old_mkdir = NULL;
extern char vault_path[MAX_LENGTH];

// name means the absolute path name like /etc/passwd
int check_privilege(char *name) {
	if (strncmp(name, vault_path, strlen(vault_path)) != 0)
		return PERMITTED;
	printk("auth_flag = %d\n", auth_flag);
	return auth_flag;
}

// convert relative path to absolute path
char* convert_to_absolute_path(char *dst_path) {
	char *cwd = NULL, *buf = NULL, *pre_path = dst_path;
	struct path path;
	
	if (strncmp(dst_path, SLASH, strlen(SLASH)) == 0) {
		// printk("No need to convert!\n");
		return pre_path;
	}
	dst_path = kmalloc(PATH_MAX, GFP_KERNEL);
	get_fs_pwd(current->fs, &path);
	buf = kmalloc(PATH_MAX, GFP_ATOMIC | __GFP_NOWARN | __GFP_ZERO);
	cwd = d_path(&path, buf, PATH_MAX);
	if (cwd == NULL || buf == NULL) {
		printk("Error! cwd or buf == NULL\n");
		return pre_path;
	}
	kfree(buf);
	buf = pre_path;
	strcat(dst_path, cwd);
	if (strncmp(cwd + strlen(cwd) - 1, SLASH, strlen(SLASH)) != 0) {
		strcat(dst_path, SLASH);
	}
	
	strcat(dst_path, buf);
	printk("dst_path: %s\n", dst_path);
	return dst_path;
}

asmlinkage long hooked_openat(struct pt_regs *regs) {
	/* 
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
	strncpy_from_user(name, (char *)regs->si, MAX_LENGTH);
	if (strncmp(name, VAULT_PATH, strlen(VAULT_PATH)) == 0) {
		printk("Attempt to intrude secret directory\n");
	} */
	return old_openat(regs);
}

asmlinkage long hooked_chdir(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);

	strncpy_from_user(name, (char *)regs->di, MAX_LENGTH);
	name = convert_to_absolute_path(name);
	if (name != NULL && check_privilege(name) == UNPERMITTED) {
		printk("Permission Denied. Consider using Basic File Vault to get permission.\n");
		return -1;
	}
	// printk("Chdir to %s\n", name);
	kfree(name);
	return old_chdir(regs);
}

asmlinkage long hooked_rename(struct pt_regs *regs) {
	return old_rename(regs);
}

asmlinkage long hooked_unlinkat(struct pt_regs *regs) {
	return old_unlinkat(regs);
}

asmlinkage long hooked_mkdir(struct pt_regs *regs) {
	return old_mkdir(regs);
}