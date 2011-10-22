#!/bin/bash
sudo losetup /dev/loop0 rootfs.ext3
sudo mount /dev/loop0 mnt/ext3
sudo losetup /dev/loop1 buildroot-2011.05/output/images/rootfs.ext2
sudo mount /dev/loop1 mnt/ext2

sudo cp -a mnt/ext2/* mnt/ext3/

sudo umount /dev/loop0
sudo losetup -d /dev/loop0
sudo umount /dev/loop1
sudo losetup -d /dev/loop1
