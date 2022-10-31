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
#define MAX_LENGTH 256

typedef asmlinkage long (*sys_call_fp)(struct pt_regs *regs);

extern unsigned short auth_flag;

sys_call_fp old_openat = NULL;
sys_call_fp old_chdir = NULL;
sys_call_fp old_rename = NULL;
sys_call_fp old_unlinkat = NULL;
sys_call_fp old_mkdir = NULL;

asmlinkage long hooked_openat(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
	strncpy_from_user(name, (char *)regs->si, MAX_LENGTH);
	if (strncmp(name, VAULT_PATH, strlen(VAULT_PATH)) == 0) {
		printk("Attempt to intrude secret directory\n");
	}
	return old_openat(regs);
}

asmlinkage long hooked_chdir(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
	/*
	struct path path;
	unsigned int lookup_flags = 0xffffff;
	int error;*/
	strncpy_from_user(name, (char *)regs->di, MAX_LENGTH);
	/*
	error = user_path_at(AT_FDCWD, name, lookup_flags, &path);
	if (error)
		printk("GGGGGGG\n");
	else
		printk("CWD: %s\n", path.dentry->d_name.name);*/

	if (strncmp(name, VAULT_PATH, strlen(VAULT_PATH)) == 0) {
		if (auth_flag == 0) {
			printk("Permission Denied. Consider using Basic File Vault to get permission.\n");
			return -1;
		}
	}
	printk("Chdir to %s\n", name);
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
