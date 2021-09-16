ifneq ($(KERNELRELEASE),)

obj-m           += nvme.o

lightnvm-y	:= lightnvm.o
nvme-y		+= pci.o scsi.o $(lightnvm-y)

else

KDIR := /lib/modules/$(shell uname -r)/build/
#KDIR := /home/user/work/firefly/linux-sdk/kernel

default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

endif
