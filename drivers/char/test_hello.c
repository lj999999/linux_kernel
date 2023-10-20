#include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/fs.h>
 #include <linux/init.h>
 #include <asm/io.h>         //含有iomap函数iounmap函数
 #include <asm/uaccess.h>    //含有copy_from_user函数
 #include <linux/device.h>   //含有类相关的处理函数

int init_hello_module(void)
{
     printk("***************Start***************\n");
     printk("Hello World Init! \n");
      return 0;
}

void exit_hello_module(void)
{
    printk("***************End***************\n");
    printk("Hello World Exit! \n");
}

module_init(init_hello_module);
module_exit(exit_hello_module);

MODULE_LICENSE("Dual BSD/GPL");//一般放到最后
