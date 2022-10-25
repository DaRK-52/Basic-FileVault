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

#define LOG_LEVEL KERN_ALERT
#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)
#define VAULT_PATH "/home/zhuwenjun/secret"
#define MAX_LENGTH 256
#define TIMEOUT 900

// sys_call_fp means system call function pointer
typedef asmlinkage long (*sys_call_fp)(struct pt_regs *regs);

unsigned long *sys_call_table = NULL;
sys_call_fp old_openat = NULL;
sys_call_fp old_chdir = NULL;
sys_call_fp old_rename = NULL;
sys_call_fp old_unlinkat = NULL;
sys_call_fp old_mkdir = NULL;
unsigned int level;
pte_t *pte;
unsigned short auth_flag = 0;

struct timer_list timer;

void find_kln_addr(void);
unsigned long *find_sys_call_table(void);

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
	strncpy_from_user(name, (char *)regs->di, MAX_LENGTH);
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

void reset_auth_flag(struct timer_list *timer01) {
	auth_flag = 0;
	printk("Timer success!\n");
}

void init_timer(void) {
	timer.expires = jiffies + msecs_to_jiffies(TIMEOUT);
	timer_setup(&timer, reset_auth_flag, 0);
}

void start_timer(void) {
	mod_timer(&timer, timer.expires);
}

void modify_sys_call_table(void) {
	// save old system call
	old_openat = ((sys_call_fp *)(sys_call_table))[__NR_openat];
	old_chdir = ((sys_call_fp *)(sys_call_table))[__NR_chdir];
	old_rename = ((sys_call_fp *)(sys_call_table))[__NR_rename];
	old_unlinkat = ((sys_call_fp *)(sys_call_table))[__NR_unlinkat];
	old_mkdir = ((sys_call_fp *)(sys_call_table))[__NR_mkdir];

	// find page table entry of system call table
	// and allow modifying it
	pte = lookup_address((unsigned long)sys_call_table, &level);
	printk("Page table entry is at 0x%lx\n", (unsigned long)pte);
	// set flag of pte atomically
	set_pte_atomic(pte, pte_mkwrite(*pte));
	sys_call_table[__NR_openat] = (unsigned long) hooked_openat;
	sys_call_table[__NR_chdir] = (unsigned long) hooked_chdir;
	sys_call_table[__NR_rename] = (unsigned long) hooked_rename;
	sys_call_table[__NR_unlinkat] = (unsigned long) hooked_unlinkat;
	sys_call_table[__NR_mkdir] = (unsigned long) hooked_mkdir;
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

void restore_sys_call_table(void) {
	pte = lookup_address((unsigned long)sys_call_table, &level);
	set_pte_atomic(pte, pte_mkwrite(*pte));
	sys_call_table[__NR_openat] = (unsigned long) old_openat;
	sys_call_table[__NR_chdir] = (unsigned long) old_chdir;
	sys_call_table[__NR_rename] = (unsigned long) old_rename;
	sys_call_table[__NR_unlinkat] = (unsigned long) old_unlinkat;
	sys_call_table[__NR_mkdir] = (unsigned long) old_mkdir;
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

static int hooked_init(void) {
	printk(LOG_LEVEL "init");
	init_timer();
	find_kln_addr();
	sys_call_table = find_sys_call_table();
	if(sys_call_table == NULL) {
		printk("System call table not found.\n");
		return 0;
	}
	printk("System call table is at 0x%lx 0x%lx\n", *sys_call_table, (unsigned long) sys_call_table);
	modify_sys_call_table();
	return 0;
}

static void hooked_exit(void) {
	del_timer(&timer);
	restore_sys_call_table();
	printk(LOG_LEVEL "exit");
}

module_init(hooked_init);
module_exit(hooked_exit);

MODULE_LICENSE("GPL");
