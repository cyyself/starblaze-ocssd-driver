
build:
	cd lightnvm; make; #ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-;
	cd ..;
	cp lightnvm/Module.symvers nvme/host/;
	cd nvme/host; make; #ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-;
	ls -l lightnvm/*.ko nvme/host/*.ko

insmod: build
	-echo 8 > /proc/sys/kernel/printk
	sudo dmesg -C
	sudo insmod lightnvm/pblk_core.ko
	sudo insmod nvme/host/nvme.ko
	sudo insmod lightnvm/pblk_main.ko
#	sudo insmod /usr/src/kernel/kernel-4.4/fs/ocfs/ocfs.ko

rmmod: remove
	-sudo rmmod pblk_main
	-sudo rmmod nvme
	-sudo rmmod pblk_core

create:
	sudo nvme lnvm create -d nvme0n1 -n ocfs -t pblk
factory:
	sudo nvme lnvm create -d nvme0n1 -n ocfs -t pblk -f
	sudo nvme lnvm create -d nvme1n1 -n ocfs1 -t pblk -f
remove:
	-sudo nvme lnvm remove -n ocfs
	-sudo nvme lnvm remove -n ocfs1
mount:
	mkfs.ocfs /dev/ocfs
	-mkdir /tmp/oc_fs
	mount -t ocfs /dev/ocfs /tmp/oc_fs
mntbtrfs:
	mkfs.btrfs /dev/ocfs
	-mkdir /mnt/test
	mount -t btrfs /dev/ocfs /mnt/test
remount:
	sudo mkdir /tmp/oc_fs
	sudo mount -t ocfs /dev/ocfs /tmp/oc_fs
umount:
	-sudo umount -t ocfs /tmp/oc_fs
	-sudo rm /tmp/oc_fs -r

clean:
	make -C lightnvm/ clean
	make -C nvme/host clean
