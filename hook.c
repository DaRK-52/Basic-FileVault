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

#define LOG_LEVEL KERN_ALERT
#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

unsigned long *sys_call_table = NULL;
unsigned long int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0) {
	kln_addr = (--regs->ip);
	return 0;
}

KPROBE_PRE_HANDLER(handler_pre1) {
	return 0;
}

static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler) {
	int ret;
	kp->symbol_name = symbol_name;
	kp->pre_handler = handler;

	ret = register_kprobe(kp);
	return ret;
}

static void find_kln_addr(void) {
	int ret;
	ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
	ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
	unregister_kprobe(&kp0);
  	unregister_kprobe(&kp1);
	printk("KLN ADDR: 0x%lx\n", kln_addr);
	kln_pointer = (unsigned long (*)(const char *name)) kln_addr;
	return;
}

unsigned long *find_sys_call_table(void) {
	return (unsigned long *) kln_pointer("sys_call_table");
}

static int hooked_init(void) {
	printk(LOG_LEVEL "init");
	find_kln_addr();
	sys_call_table = find_sys_call_table();
	if(sys_call_table == NULL) {
		printk("System call table not found.\n");
		return 0;
	}
	printk("System call table is at 0x%lx\n", *sys_call_table);
	return 0;
}

static void hooked_exit(void) {
	printk(LOG_LEVEL "exit");
}

module_init(hooked_init);
module_exit(hooked_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DaRK52");
