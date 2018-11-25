#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>

#include "anti_driver.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("KGVC");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("This is for the CSE331 anti-virus project");


asmlinkage int (*old_open)(const char *filename, int flags, int mode);
//asmlinkage int (*old_execve)(const char *filename, int flags, int mode);


int 
set_addr_rw(long unsigned int _addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}


int 
set_addr_ro(long unsigned int _addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}




int anti_open(struct inode *inodep, struct file *filp){
    printk(KERN_ALERT "inside the %s function\n", __FUNCTION__);
    return 0;
}
int anti_close(struct inode *inodep, struct file *filp){
    printk(KERN_ALERT "inside the %s function\n", __FUNCTION__);
    return 0;
}
ssize_t anti_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
    printk(KERN_ALERT "inside the %s function\n", __FUNCTION__);
    return count;
}
ssize_t anti_write(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
    printk(KERN_ALERT "inside the %s function\n", __FUNCTION__);
    return count;
}


// asmlinkage int
// anti_open(const char *filename, int flags, int mode)
// {
//     printk(KERN_INFO "Intercepting open(%s, %X, %X)\n", filename, flags, mode);
//     return (*old_open)(filename, flags, mode);
// }




static int __init
init(void)
{
    printk(KERN_INFO "++++++++++++ ANTI PROJECT INIT FUNC ++++++++++++\n");
    int result = register_chrdev(ANTI_MAJOR, "anti", &anti_fops);
    if (result < 0) // fail to register device
        return result;
    //memset(buffer, 0, sizeof buffer);
    //set_addr_rw((unsigned long) sys_call_table);
    //old_open = (void *) sys_call_table[__NR_open];
    //sys_call_table[__NR_open] = anti_open;
    return 0;
}

static void __exit
cleanup(void)
{
    unregister_chrdev(ANTI_MAJOR, "anti");
    memset(buffer, 0, sizeof buffer);
    sys_call_table[__NR_open] = old_open;
    set_addr_ro((unsigned long) sys_call_table);
    printk(KERN_INFO "------------ ANTI PROJECT EXIT FUNC ------------\n");
    return;
}

module_init(init);
module_exit(cleanup);








