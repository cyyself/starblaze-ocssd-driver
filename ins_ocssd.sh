#!/bin/bash
echo "Start sequence write/read test.."
cd ~/firefly_4.4.154

sudo make rmmod
sleep 1s
sudo make insmod
sleep 1s
#sudo insmod f2fs.ko
#sleep 1s
sudo make factory
#sudo nvme lnvm create -d nvme1n1 -n ocfs1 -t pblk -f
#sleep 3s
#sudo make mntbtrfs
#sleep 3s
#cd test
#sudo fio write.fio --bandwidth-log --output=write_result.txt;cp agg-write_bw.log agg-write_bw_write.log; sudo fio read.fio --bandwidth-log --output=read_result.txt;cp agg-read_bw.log agg-read_bw_read.log
echo "End test."
