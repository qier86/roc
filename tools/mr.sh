#!/bin/bash
 
echo "Modify the ramdisk.img"
 
echo "1.Exact  Ramdisk"
echo "2.Create image"
 
read -p "Choose:" CHOOSE
 
#case ${CHOOSE} in
#1)inflate();;
#2)create() ;;
#esac
 
 
if [ "1" = ${CHOOSE} ];then
	rm -rf tmp
	mkdir tmp
	cp ramdisk.img tmp/ramdisk.cpio.gz
	cd tmp
	gzip -d ramdisk.cpio.gz
	cpio -i -F ramdisk.cpio
	rm ramdisk.cpio
	echo "Exact OK."
elif [ "2" = ${CHOOSE} ];then
	cd tmp
	find . | cpio -o -H newc | gzip > ../newramdisk.img
	cp ../newramdisk.img ~/project/changbai/kernel/ramdisk.img
	echo "Create OK "
 
fi
