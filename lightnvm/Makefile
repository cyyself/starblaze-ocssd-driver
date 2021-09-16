# Makefile for Open-Channel SSDs.
#
ifneq ($(KERNELRELEASE),)

obj-m		+= pblk_core.o
obj-m		+= pblk_main.o

pblk_core-y := core.o
pblk_main-y	:= pblk-init.o pblk-core.o pblk-rb.o \
		       pblk-write.o pblk-cache.o pblk-read.o \
			   pblk-gc.o pblk-recovery.o pblk-map.o \
			   pblk-rl.o pblk-sysfs.o

else

KDIR := /lib/modules/$(shell uname -r)/build/
#KDIR := /home/user/work/firefly/linux-sdk/kernel

default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

endif
