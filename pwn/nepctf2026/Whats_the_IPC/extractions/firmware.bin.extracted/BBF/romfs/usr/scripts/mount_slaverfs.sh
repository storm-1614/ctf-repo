#! /bin/sh

if [ -c /dev/ubi_ctrl ];then

ubiattach -m 6 /dev/ubi_ctrl

if [ -c /dev/ubi1_0 ];then
mount -t ubifs -o sync /dev/ubi1_0 /home/
fi

fi
