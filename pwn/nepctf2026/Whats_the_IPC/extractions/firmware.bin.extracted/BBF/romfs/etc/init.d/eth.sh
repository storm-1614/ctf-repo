#! /bin/sh

cmdline=`cat /proc/cmdline`

tmp=`echo ${cmdline#*ipaddr=}`
ipaddr=`echo ${tmp%% *}`

tmp=`echo ${cmdline#*ethaddr=}`
ethaddr=`echo ${tmp%% *}`

if [ -e /usr/ko/libphy.ko ];then
	insmod /usr/ko/libphy.ko
fi
if [ -e /usr/ko/fixed_phy.ko ];then
	insmod /usr/ko/fixed_phy.ko
fi
if [ -e /usr/ko/realtek.ko ];then
	insmod /usr/ko/realtek.ko
fi
if [ -e /usr/ko/of_mdio.ko ];then
	insmod /usr/ko/of_mdio.ko
fi

#1000Mpbs
#phyio : rgmii = 0x01; mii = 0x00; rmii = 0x04
#insmod /usr/ko/gmac.ko phyaddr=1 phyhid=0x0362 phylid=0x5CC6 phyio=0x01

#100Mpbs
#phyio : rgmii = 0x01; mii = 0x00; rmii = 0x04
if [ -e /usr/ko/gmac.ko ];then
	insmod /usr/ko/gmac.ko phyaddr=0x00 phymode=0x0
fi

ifconfig eth0 hw ether $ethaddr
ifconfig eth0 up
ifconfig eth0 $ipaddr netmask 255.255.252.0

#ip -6 addr add fe80::211:1187:35d5:b411/64 dev eth0

route add default gw 10.35.39.254
mount -t nfs -o nolock 10.35.36.1:/nfspool/romfs/home /mnt/nfs
telnetd &
