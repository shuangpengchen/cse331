#ifndef ANTI_DRIVER_H
#define ANTI_DRIVER_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/uaccess.h>
#define ANTI_MAJOR   60
#define BUFF_LENGTH 255


char buffer[BUFF_LENGTH+1];
char* bptr = buffer;
const char* endptr = (buffer+sizeof(buffer)-1);




int anti_open(struct inode *inodep, struct file *filp);
//int anti_close(struct inode *inodep, struct file *filp);
//ssize_t anti_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t anti_write(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
void anti_exit(void);
int anti_init(void);

struct file_operations anti_fops = {
  .owner = THIS_MODULE,
  //.read = anti_read,
  .open = anti_open,
  //.release = anti_close,
  .write = anti_write,
};

#endif
