obj-m = anti_driver.o
KERNEL = $(shell uname -r)
PWD = $(shell pwd)

all:
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) clean
