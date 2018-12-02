#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include "anti_driver.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("KGVC");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("This is for the CSE331 anti-virus project");

unsigned long *sys_call_table = (unsigned long) 0xc175f180;
asmlinkage int (*old_open)(const char *filename, int flags, int mode);
//asmlinkage int (*old_execve)(const char *filename, int flags, int mode);


int set_addr_rw(long unsigned int _addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

int set_addr_ro(long unsigned int _addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
}




// static int invoke_user_space_process(char *message ){
//   struct subprocess_info *sub_info;
//   char *argv[] = { "/usr/bin/logger", message, NULL };
//   static char *envp[] = {
//         "HOME=/",
//         "TERM=linux",
//         "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

//   sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC );
//   if (sub_info == NULL) return -ENOMEM;

//   return call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );
// }

 int invoke_user_space_process(const char *message )
{
 char *argv[] = { "/usr/bin/logger", message , NULL };
 static char *envp[] = {
       "HOME=/",
       "TERM=linux",
       "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
 return call_usermodehelper( argv[0], argv, envp, UMH_WAIT_PROC );
}


// read write open close operation of char device for com between kernel and user space
int anti_open(struct inode *inodep, struct file *filp){
    printk(KERN_ALERT "Inside the %s function And Open Device[-anti-] \n ", __FUNCTION__);
    return 0;
}
ssize_t anti_write(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
    printk(KERN_ALERT "Inside the %s function\n Write Data from user space -> kernel\n", __FUNCTION__);

    int ret;
    ret = copy_from_user(buffer,buf,1);
    if(ret) {
        printk(KERN_DEBUG " Can't copy from user space buffer\n");
        return -EFAULT;
    }
    printk(KERN_ALERT "BEFORE\n");
    printk(KERN_ALERT "THE DATA IS : %c\n ", buffer[0]);
    printk(KERN_ALERT "AFTER\n");
    return count;
}

asmlinkage int
new_open(const char *filename, int flags, int mode)
{
    
    if(flags == 32768 && strcmp(filename,"Makefile") != NULL){
        printk(KERN_INFO "----->>>>>> Intercepting open(%s, %d, %d)\n", filename, flags, mode);
        invoke_user_space_process(filename);
    }else{
        printk(KERN_INFO "others Intercepting open(%s, %d, %d)\n", filename, flags, mode);
    }
    return (*old_open)(filename, flags, mode);

}


static int __init
init(void)
{
    printk(KERN_INFO "++++++++++++ ANTI PROJECT INIT FUNC ++++++++++++\n");
    //invoke_user_space_process("init");
    int result;
    result = register_chrdev(ANTI_MAJOR, "anti", &anti_fops);
    if (result < 0){ // fail to register device
        printk(KERN_INFO "fail to load driver\n");
        return result;
    }
    memset(buffer, 0, sizeof buffer);
    set_addr_rw((unsigned long) sys_call_table);
    old_open = (void *) sys_call_table[__NR_open];
    sys_call_table[__NR_open] = new_open;
    printk(KERN_INFO "++++++++++++ ANTI PROJECT INIT FUNC +++++++DONE+++++\n");
    return 0;
}

static void __exit
cleanup(void)
{
    printk(KERN_INFO "------------ ANTI PROJECT EXIT FUNC ------------\n");
    //invoke_user_space_process("exit");
    unregister_chrdev(ANTI_MAJOR, "anti");
    memset(buffer, 0, sizeof buffer);
    sys_call_table[__NR_open] = old_open;
    set_addr_ro((unsigned long) sys_call_table);
    printk(KERN_INFO "------------ ANTI PROJECT EXIT FUNC -------DONE-----\n");
    return;
}

module_init(init);
module_exit(cleanup);








