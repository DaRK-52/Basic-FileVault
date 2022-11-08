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
#include <crypto/hash.h>

#define VAULT_MANAGER "vault_manager"
#define VAULT_MANAGER_MD5 "e0955fb90dd17b6aea7fc57e8427d50f"
#define SLASH "/"
#define SECRET "secret"
#define MAX_LENGTH 256
#define PERMITTED 1
#define UNPERMITTED 0
#define MD5_SIZE 16

typedef asmlinkage long (*sys_call_fp)(struct pt_regs *regs);

unsigned short auth_flag = 0;

sys_call_fp old_openat = NULL;
sys_call_fp old_chdir = NULL;
sys_call_fp old_rename = NULL;
sys_call_fp old_unlinkat = NULL;
sys_call_fp old_mkdir = NULL;
extern char vault_path[MAX_LENGTH];
extern char passwd_md5_path[MAX_LENGTH];

bool md5_hash(char *result, char* data, size_t len){
    struct shash_desc *desc;
	char buf[64];
	int i;

    desc = kmalloc(sizeof(*desc), GFP_KERNEL);
    desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);

    if(desc->tfm == NULL)
        return false;

    crypto_shash_init(desc);
    crypto_shash_update(desc, data, len);
    crypto_shash_final(desc, result);
    crypto_free_shash(desc->tfm);

	for (i = 0;i < MD5_SIZE;i++) {
		sprintf(buf + i*2, "%02x", result[i] & 0xff);
	}
	if (strncmp(buf, VAULT_MANAGER_MD5, strlen(VAULT_MANAGER_MD5)) == 0) {
		return true;
	}
    return false;
}

// name means the absolute path name like /etc/passwd
int check_privilege(char *name) {
	// second condition avoid different directory with same prefix
	// like /home/zhuwenjun/secret and /home/zhuwenjun/secret2
	if (strncmp(name, vault_path, strlen(vault_path)) != 0 
		|| (strlen(name) > strlen(vault_path) && strncmp(name + strlen(vault_path), SLASH, strlen(SLASH) != 0)))
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
	// printk("dst_path: %s\n", dst_path);
	return dst_path;
}

// need reconsider how to authenticate vault manager
int is_open_by_manager(void) {
	char *buf = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
	
	if (md5_hash(buf, current->comm, strlen(current->comm)))
		return 1;
	kfree(buf);
	return 0;
}

asmlinkage long hooked_openat(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);
	
	strncpy_from_user(name, (char *)regs->si, MAX_LENGTH);
	name = convert_to_absolute_path(name);
	if (check_privilege(name) == UNPERMITTED) {
		if (strncmp(name, passwd_md5_path, strlen(passwd_md5_path)) == 0 && is_open_by_manager()) {
			printk("current command: %s\n", current->comm);
			goto end;
		}
		printk("Permission Denied(openat). Consider using Basic File Vault to get permission.\n");
		kfree(name);
		return -1;
	}
end:
	kfree(name);
	return old_openat(regs);
}

asmlinkage long hooked_chdir(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);

	strncpy_from_user(name, (char *)regs->di, MAX_LENGTH);
	name = convert_to_absolute_path(name);
	if (name != NULL && check_privilege(name) == UNPERMITTED) {
		printk("Permission Denied(chdir). Consider using Basic File Vault to get permission.\n");
		kfree(name);
		return -1;
	}
	kfree(name);
	return old_chdir(regs);
}

asmlinkage long hooked_rename(struct pt_regs *regs) {
	char *src_name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL),
		*dst_name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);

	strncpy_from_user(src_name, (char *)regs->di, MAX_LENGTH);
	strncpy_from_user(dst_name, (char *)regs->si, MAX_LENGTH);
	src_name = convert_to_absolute_path(src_name);
	dst_name = convert_to_absolute_path(dst_name);\
	printk("src name: %s, dst name: %s\n", src_name, dst_name);
	if (check_privilege(src_name) == UNPERMITTED || check_privilege(dst_name) == UNPERMITTED) {
		printk("Permission Denied(rename). Consider using Basic File Vault to get permission.\n");
		kfree(src_name);
		kfree(dst_name);
		return -1;
	}
	
	kfree(src_name);
	kfree(dst_name);
	return old_rename(regs);
}

asmlinkage long hooked_unlinkat(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);

	strncpy_from_user(name, (char *)regs->si, MAX_LENGTH);
	name = convert_to_absolute_path(name);
	if (check_privilege(name) == UNPERMITTED) {
		printk("Permission Denied(unlinkat). Consider using Basic File Vault to get permission.\n");
		kfree(name);
		return -1;
	}

	kfree(name);
	return old_unlinkat(regs);
}

asmlinkage long hooked_mkdir(struct pt_regs *regs) {
	char *name = (char *)kmalloc(MAX_LENGTH, GFP_KERNEL);

	strncpy_from_user(name, (char *)regs->di, MAX_LENGTH);
	name = convert_to_absolute_path(name);
	if (check_privilege(name) == UNPERMITTED) {
		printk("Permission Denied(unlinkat). Consider using Basic File Vault to get permission.\n");
		kfree(name);
		return -1;
	}

	kfree(name);
	return old_mkdir(regs);
}