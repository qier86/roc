#!/bin/bash

#This script is used to build products including vtc source code.
#It should be under top path of whole project via a symbol link.
#Warning: pure vt evb5850 product can't built with this script.

#Path to Images and configuration files to be burned into target device
TOPPATH=`pwd`"/"
ProductFinalOutputDir="out/"
ProductFinalOutputPath=$TOPPATH$ProductFinalOutputDir

#Cross compile tool type for android, kernel, and uboot
CROSS_COMPILE=arm-none-linux-gnueabi-
processnum=$(cat /proc/cpuinfo|grep "process" | wc -l )
threadNum="-j""$processnum"

#VTC variables
VTCTopDir="viatelecom/"
VTCTopPath=$TOPPATH$VTCTopDir
VTCSystemSrcPath="$VTCTopPath"system/
VTCKernelSrcPath="$VTCTopPath"kernel/
VTCUBootSrcPath="$VTCTopPath"uboot/
VTCProductPath="$VTCTopPath"product/
VTCProductDir="$VTCTopDir"product/

VTCDefaultProductName="qilian"
VTCProductName=$VTCDefaultProductName
VTCDefaultKernelConfigName=$VTCDefaultProductName"_defconfig"
VTCKernelConfigName=$VTCDefaultKernelConfigName
VTCDefaultUBootConfigName=$VTCDefaultProductName"_boards.cfg"
VTCUBootConfigName=$VTCDefaultUBootConfigName

#Android variables
AndroidDir="android_4.2.2_r1/"
AndroidPath=$TOPPATH$AndroidDir
AndroidEnvsetupPath=$AndroidPath"build/envsetup.sh" 
AndroidLunchProduct="full_"$VTCProductName"-eng"
AndroidLocalOutPutPath=$AndroidPath"out/target/product/"$VTCProductName
AndroidLocalOutRootPath=$AndroidLocalOutPutPath"/root/"
AndroidFinalOutputPath=$ProductFinalOutputPath"android_rootfs"

makebootimgtool=$AndroidPath"out/host/linux-x86/bin/mkbootimg"

#Kernel variables
KernelDir="kernel_3.4.39/"
KernelPath=$TOPPATH$KernelDir
DTCPath=$KernelPath"scripts/dtc/dtc"
DTPath="arch/arm/boot/"
DTBPath="cbp5850.dtb"
DTSPath=$KernelPath"arch/arm/boot/dts/cbp5850.dts"
CFBDriverPath=$KernelPath"drivers/video/"
CFBDriverLinunxPath=$KernelPath"drivers/video/cbp5850/linux/"
MaliDriverPath=$KernelPath"drivers/gpu/arm/mali/"
UmpDriverPath=$KernelPath"drivers/gpu/arm/ump/"
KernelFinalOutputPath=$ProductFinalOutputPath"kernel"
KernelName="uImage"
KernelConfigName="cbp5850_defconfig"

CFBDriverOutLinunxPath="/lib/modules/3.4.39/kernel/drivers/video/cbp5850/linux/"
CFBDriverOutPath="/lib/modules/3.4.39/kernel/drivers/video/"
MaliDriverOutPath="/lib/modules/3.4.39/kernel/drivers/gpu/arm/mali/"
UmpDriverOutPath="/lib/modules/3.4.39/kernel/drivers/gpu/arm/ump/"

#UBoot variables
UBootDir="uboot_201304/"
UBootPath=$TOPPATH$UBootDir
UBootName="u-boot"
UBootFinalOutputPath=$ProductFinalOutputPath"uboot/"

#MMC variables
MMCDevName="/dev/sdb"
MMCBootPath="/media/boot"
MMCSystemPath="/media/system"
MMCBootPartSize="+300M"
MMCRecoveryDir="/media/recovery"

#OTA variables
OTABspPath=$ProductFinalOutputPath"bspinst/"
OTAbspPackagePath=$OTABspPath"packages/"
OTAbspinst_array=("bspinst.cfg" "initrd.img" "kernel-logo.data" "u-boot.bin" "u-boot-logo.data" "w-load.bin" "fundamental_rootfs.android.tgz" "boot.img" "recovery.img" "ramdisk.img" "ramdisk-recovery.img" "uzImage.bin" "cbp5850.dtb")

#Touch variables
MMCRecoveryDir="/media/recovery/"
TouchPlaneARGS=" cbpfb_bus=dsi cbpfb_busmode=video cbpfb_dev=nt35590 cbpfb_mode=720x1280@60 cbpfb_bpp=32"
TouchPlaneARGSFile=$AndroidFinalOutputPath"/init.via.rc"
makeyaffstool=${AndroidPath}"device/via/evb5850/tools/mkyaffs2image"

#Build variables
BBuild=0
BBuildKernel=0
BBuildAndroid=0
BBuildUBoot=0
BPortToMMC=0
BOta=0
Bplane=0

#Clean variables
BClean=0
BCleanAndroid=0
BCleanKernel=0
BCleanUBoot=0

errout()
{
    local errmesg="vtc_build.sh:"$1
    echo -e "\033[40;41m "$errmesg"\033[0m"
    [ "$2" == "1" ] && cd - >/dev/null 2>&1
    [ "$2" == "2" ] && return
    exit 1
}

delOTAcopyArr()
{
    [ $# -eq 1 ] || errout "delOTAcopyArr error "

    for ((i=0;i<${#OTAbspinst_array[@]};i++))
    do
        [ "${OTAbspinst_array[$i]}" != "$1" ] || unset OTAbspinst_array[$i]
    done
}


MakeOTAOutDirs()
{
    [ $BOta -eq 1 ] || return
    [ -d $ProductFinalOutputPath ] || mkdir $ProductFinalOutputPath
    [ -d $OTABspPath ] || mkdir $OTABspPath
    [ -d $OTAbspPackagePath ] || mkdir $OTAbspPackagePath
}

buildAndroid()
{
    echo "=============build Android============"
    [ -d "$AndroidPath" ] || errout "can not find path : $AndroidPath "

    cd "$AndroidPath"

    [ -e "$AndroidEnvsetupPath" ] || errout "file not exist : $AndroidEnvsetupPath" 1
     
    echo "exec AndroidEnvsetupPath"
    source "$AndroidEnvsetupPath" 
   
    echo "lunch $AndroidLunchProduct config" 
    lunch $AndroidLunchProduct || errout "lunch $AndroidLunchProduct failed" 1
    
    echo "make Android $threadNum"
    make $threadNum CROSS_COMPILE=$CROSS_COMPILE ARCH=arm || errout "make android failed" 1
    cd - >/dev/null 2>&1

    echo "=============build Android done=========="
}

buildUBoot()
{
    echo "=============build uboot============"
    [ -d "$UBootPath" ] || errout "can not find path : $UBootPath "

    cd "$UBootPath"

    echo "make cbp5850..."

    make cbp5850 CROSS_COMPILE=$CROSS_COMPILE ARCH=arm || error "uboot :make cbp5850 error" 1

    #echo "make zuboot..."
    #$make zuboot.bin "CROSS_COMPILE=$CROSS_COMPILE" $threadNum|| errout "uboot :make zuboot error" 1

    cd - >/dev/null 2>&1

    echo "=============build uboot done=========="
}

cpOtaUBoot()
{
    [ $BOta -eq 1 ] || return

    echo "uboot : copying uboot to bsp"
    cp "$UBootFinalOutputPath""$UBootName" $OTABspPath|| errout "uboot:copying uboot failed: $UBootFinalOutputPath$UBootName" 2

    delOTAcopyArr "u-boot.bin"
}

cpUBootfile()
{
    echo "===============copy uboot files=============="

    if [ ! -d "$ProductFinalOutputPath" ];then
        mkdir $ProductFinalOutputPath -p
    fi

    if [ ! -d $UBootFinalOutputPath ];then
        mkdir $UBootFinalOutputPath
    fi
    echo "copy $UBootPath $UBootName to $UBootFinalOutputPath"
    if [ -e "$UBootPath""$UBootName" ];then
	cp "$UBootPath""$UBootName" $UBootFinalOutputPath -rf 
    else
        errout "no $UBootName found in $UBootPath" 
    fi

    cpOtaUBoot
    echo "===============copy uboot files done=============="

}

cpOtaAndroid()
{
    [ $BOta -eq 1 ] || return    
    
    MakeOTAOutDirs    
    
    local rootfs="$AndroidLocalOutPutPath""/system/"
    local bootimg="$AndroidLocalOutPutPath""/boot.img"
    local recoveryimg="$AndroidLocalOutPutPath""/recovery.img"
    local ramdiskimg="$AndroidPath""$AndroidLocalOutPutPath""/ramdisk.img"
    local ramdiskrecoveryimg="$AndroidLocalOutPutPath""/ramdisk-recovery.img"
    [ -d $rootfs ] || errout "ota :dir not exist : $rootfs" 2
    
    echo "ota:tar android system..."
    tar zcf "fundamental_rootfs.android.tgz" -C $rootfs . || errout "ota:tar $rootfs failed" 2
    
    echo "ota:movimg tar files to $OTAbspPackagePath..."
    mv "fundamental_rootfs.android.tgz" $OTAbspPackagePath || errout "ota:moving $OTAbspPackagePath failed" 2

    echo "ota:copying boot.img"
    cp $bootimg $OTABspPath || errout "ota:copying bootimg failed: $bootimg" 2

    echo "ota:copying recoveryimg"
    cp $recoveryimg $OTABspPath || errout "ota:copying recoveryimg failed: $recoveryimg" 2

    echo "ota:copying ramdiskimg"
    cp $ramdiskimg $OTABspPath|| errout "ota:copying ramdiskimg failed: $ramdiskimg" 2

    echo "ota:copying ramdiskrecoveryimg"
    cp $ramdiskrecoveryimg $OTABspPath|| errout "ota:copying ramdiskrecoveryimg failed: $ramdiskrecoveryimg" 2

    delOTAcopyArr "boot.img"   
    delOTAcopyArr "fundamental_rootfs.android.tgz"
    delOTAcopyArr "recovery.img"
    delOTAcopyArr "ramdisk.img"
    delOTAcopyArr "ramdisk-recovery.img"
}

modifyCFBArgs()
{
    echo "=================modifyCFBargs:============="
    [ -e $TouchPlaneARGSFile ] || errout "can not find file $TouchPlaneARGSFile"
    sed -i 's/cbp5850_fb.ko cbpfb_mode=800x600@60/cbp5850_fb.ko cbpfb_bus=dsi cbpfb_busmode=video cbpfb_dev=nt35590h cbpfb_mode=720x1280@60 cbpfb_bpp=32/g' $TouchPlaneARGSFile
    #sed -n 's/cbp5850_fb.ko/cbp5850_fb.ko cbpfb_bus=dsi cbpfb_busmode=video cbpfb_dev=nt35590h cbpfb_mode=720x1280@60 cbpfb_bpp=32/g' $TouchPlaneARGSFile   
    echo "=================modifyCFBargs done:============="
}

cpAndroidFileSys()
{
    echo "=============cp Android  file  system============"
    [ -d "$AndroidLocalOutPutPath" ] || errout "can not find path : ""$AndroidLocalOutPutPath "

    if [ ! -d "$ProductFinalOutputPath" ];then
        mkdir $ProductFinalOutputPath -p 
    fi
    
    if [ ! -d $AndroidFinalOutputPath ];then
        mkdir $AndroidFinalOutputPath 
    fi
    
    echo "copy root fs to $AndroidFinalOutputPath"
    if [ -d "$AndroidLocalOutRootPath" ];then
        cp "$AndroidLocalOutRootPath"* $AndroidFinalOutputPath -rf
    else
        errout "dir not exist:""$AndroidLocalOutRootPath" 2
    fi
    
    echo "copying drivers to android root file system...."
    [ -d "$AndroidFinalOutputPath""$CFBDriverOutLinunxPath" ] || mkdir "$AndroidFinalOutputPath""$CFBDriverOutLinunxPath" -p
   
    [ -d "$AndroidFinalOutputPath""$MaliDriverOutPath" ] || mkdir "$AndroidFinalOutputPath""$MaliDriverOutPath" -p

    [ -d "$AndroidFinalOutputPath""$UmpDriverOutPath" ] || mkdir "$AndroidFinalOutputPath""$UmpDriverOutPath" -p

    [ -d $AndroidFinalOutputPath"/system/" ] && rm $AndroidFinalOutputPath"/system/"* -rf
    
	[ -d $AndroidFinalOutputPath"/data/" ] && rm $AndroidFinalOutputPath"/data/"* -rf
    
    if [ $BBuildKernel -eq 1 ];then
        if [ ! -d "$AndroidFinalOutputPath""$CFBDriverOutLinunxPath" ];then
            errout "can not find android root fs path :""$AndroidFinalOutputPath""$CFBDriverOutLinunxPath" 2
        else
#            cp "$KernelPath""$CFBDriverPath"*.ko "$AndroidFinalOutputPath""$CFBDriverOutPath"
            cp "$CFBDriverLinunxPath"*.ko "$AndroidFinalOutputPath""$CFBDriverOutLinunxPath"
            cp "$MaliDriverPath"*.ko "$AndroidFinalOutputPath""$MaliDriverOutPath"
            cp "$UmpDriverPath"*.ko "$AndroidFinalOutputPath""$UmpDriverOutPath"
        fi
    fi

	echo "makeimg ramdisk.img.."
#    find $AndroidFinalOutputPath | cpio -o -H newc | gzip > $ProductFinalOutputPath"ramdisk.img"|| errout "making ramdiskimg error..." 2
    #####make ramdisk.img################### 
    mkdir tmp
    dd if=/dev/zero of=ramdisk.img bs=1k count=10240
    mke2fs -F -v -m0 ramdisk.img
    sudo mount -o loop ramdisk.img tmp/
    cp "$AndroidFinalOutputPath""/"* tmp -arf
    
    sed -i 's/# mount yaffs2 mtd/mount yaffs2 mtd/g' tmp/init.rc
 
    sleep 2
    sudo umount tmp
    gzip ramdisk.img
    mv ramdisk.img.gz "$ProductFinalOutputPath""ramdisk.img"
    rm tmp -rf
     
    #####make ramdisk.img################### 

    [ -e $KernelFinalOutputPath"/"$KernelName ] && $makebootimgtool --kernel $KernelFinalOutputPath"/"$KernelName --ramdisk $ProductFinalOutputPath"ramdisk.img" --output $ProductFinalOutputPath"boot.img"

    echo "copy android fs to $AndroidFinalOutputPath"
    if [ -d "$AndroidLocalOutPutPath""/system/" ];then
        cp "$AndroidLocalOutPutPath""/system/" $AndroidFinalOutputPath -rf
    else
        errout "dir not exist:""$AndroidLocalOutPutPath""/system/" 2
    fi
    
    echo "tar android rootfs ..."
    pushd $ProductFinalOutputPath
	#just for fastboot debug, REMOVE ME
    #cp $TOPPATH/tools/fastboot-test.bin android_rootfs/system/

    ###############make system.img########################
    $makeyaffstool "android_rootfs/system/" system.img 4096 224 8
    ###############make system.img########################
    
	###############tar mmc boot file system########################
    tar zcf "android_rootfs.tgz"  android_rootfs  
    ###############tar mmc boot file system########################
    popd
    
	# ota  
    cpOtaAndroid
    
    echo "=============cp Android  file  system done=========="
}


buildKernel()
{
    echo "=============build Kernel ============"
 
    if [ ! -d "$KernelPath" ];then
        errout "can not find path : $KernelPath "
    fi

    cd "$KernelPath"

    echo $VTCProductName | grep -q "evb5850"
    if [[ $? -eq 0 ]]; then
        echo "make $KernelConfigName  ..."
        make $KernelConfigName || errout "make $KernelConfigName error" 1
    else 
        echo "make $VTCKernelConfigName ..."
        make ../../../../"$VTCProductDir""$VTCProductName"/"$VTCKernelConfigName" || errout "make $VTCKernelConfigName error" 1
    fi

    echo "make uImage....."
    make uImage CROSS_COMPILE=$CROSS_COMPILE ARCH=arm $threadNum || errout "make uImage.bin error" 1

    echo "make modules..."
    make modules CROSS_COMPILE=$CROSS_COMPILE ARCH=arm || errout "make modules error" 1

    echo "make device tree..."
    make cbp5850.dtb
    #$DTCPath -I dts -O dtb -o $DTBPath $DTSPath || errout "make device tree failed..skiped" 2
   
    cd - >/dev/null 2>&1
    echo "=============build Kernel done=========="
}

cpOtaKernel()
{
    [ $BOta -eq 1 ] || return
    local uImage="$KernelPath""$KernelName"
    local DTBPath="$KernelPath""$DTBPath"
    MakeOTAOutDirs
    
    echo "ota : copying uImage..."
    cp $uImage $OTABspPath|| errout "ota:copying uImage failed: $uImage" 2
    
    echo "ota : copying device tree"
    cp $DTBPath $OTABspPath|| errout "ota:copying device tree failed: $DTBPath" 2

    delOTAcopyArr "uzImage.bin"
    delOTAcopyArr "cbp5850.dtb"
}

cpKernelfile()
{
    echo "===============copy Kernel files=============="

    if [ ! -d "$ProductFinalOutputPath" ];then
        mkdir $ProductFinalOutputPath -p
    fi
    
    if [ ! -d $KernelFinalOutputPath ];then
        mkdir $KernelFinalOutputPath
    fi

    echo "copy uImage to $KernelFinalOutputPath"
    
    if [ -e "$KernelPath"arch/arm/boot/uImage ];then
        cp "$KernelPath"arch/arm/boot/uImage $KernelFinalOutputPath -rf    
    else
        errout "no $KernelName found in $KernelPath" 2
    fi
    
    echo "copy cbp5850.dtb to $KernelFinalOutputPath"
    
    if [ -e "$KernelPath""$DTBPath" ];then
        cp "$KernelPath""$DTBPath" $KernelFinalOutputPath -rf
    else
        errout "no cbp5850.dtb exist,cp *.dtb to $KernelFinalOutputPath" 2
        cp "$KernelPath""$DTPath"*.dtb $KernelFinalOutputPath -rf
    fi
    
    echo "copy fb driver to android/lib"
    if [ ! -d "$AndroidFinalOutputPath""$CFBDriverOutLinunxPath" ];then
        errout "can not find android root fs path :""$AndroidFinalOutputPath""$CFBDriverOutLinunxPath" 2
    else
#        cp "$CFBDriverPath"*.ko "$AndroidFinalOutputPath""$CFBDriverOutPath"
        cp "$CFBDriverLinunxPath"*.ko "$AndroidFinalOutputPath""$CFBDriverOutLinunxPath"
        cp "$MaliDriverPath"*.ko "$AndroidFinalOutputPath""$MaliDriverOutPath"
        cp "$UmpDriverPath"*.ko "$AndroidFinalOutputPath""$UmpDriverOutPath"
    fi

    [ -e $ProductFinalOutputPath"ramdisk.img" ] && $makebootimgtool --kernel $KernelFinalOutputPath"/"$KernelName --ramdisk $ProductFinalOutputPath"ramdisk.img" --output $ProductFinalOutputPath"boot.img"
    cpOtaKernel
	
    echo "===============copy kernel files done========"
}

usage() 
{
    echo "                                                                 "
    echo "Usage: `basename $0` [OPTION]...                                 "
    echo "                                                                 "
    echo "Description:                                                     "
    echo "  -p    set product name to build or clean, default \"qilian\"   "
    echo "  -o    set project output path, default \"./out\"               "
    echo "  -b    set build target,  default target \"all\"                "
    echo "        support [all|android|kernel|uboot|tommc|ota|touch]       "
    echo "  -c    set clean target,  default target \"all\"                "
    echo "        support [all|android|kernel|uboot]                       "
    echo "                                                                 "
    echo "Examples:                                                        "
    echo "  ./`basename $0` -p qilian -b all                               "
    echo "        build android, kernel and uboot for qilian product       "
    echo "  ./`basename $0` -p qilian -b android                           "
    echo "        build android only for qilian product                    "
    echo "  ./`basename $0` -p qilian -c all                               "
    echo "        clean android, kernel and uboot for qilian product       "
    echo "  ./`basename $0` -p qilian -c kernel                            "
    echo "        clean kernel only for qilian product                     "
    echo "  ./`basename $0` -p qilian -b all -o ./out                      "
    echo "        set final project output path to ./out and build product "
    echo "                                                                 "

    exit
}

parseArgs()
{
    while [ $# -gt 0 ];do
        case $1 in
        "-o") 
            shift

            if [ $# -le 0 ] || [[ "$1" == "-"* ]] ;then
                echo "should set a output dir"
                usage
            else
                ProductFinalOutputPath=$1
                [[ "$ProductFinalOutputPath" == *"/" ]] || ProductFinalOutputPath=$ProductFinalOutputPath"/"
                AndroidFinalOutputPath=$ProductFinalOutputPath"android_rootfs"
                KernelFinalOutputPath=$ProductFinalOutputPath"kernel"
                OTABspPath=$ProductFinalOutputPath"bspinst/"
                OTAbspPackagePath=$OTABspPath"packages"

                shift
            fi
        ;;

        
        "-p")
            shift
            if [ $# -gt 0 ] && [[ "$1" != "-"* ]] ;then
                VTCProductName=$1
                AndroidLunchProduct="full_"$VTCProductName"-eng"
                shift
            fi
        ;;

        "-b")
            shift
            BBuild=1
            if [ $# -le 0 ];then
                BBuildAndroid=1
                BBuildKernel=1
                BBuildUBoot=1
            else
                case $1 in 
                    "all")
                        BBuildAndroid=1
                        BBuildKernel=1
                        BBuildUBoot=1
                    ;;

                    "android")
                        BBuildAndroid=1
                    ;;

                    "kernel")
                        BBuildKernel=1
                    ;;

                    "uboot")
                        BBuildUBoot=1
                    ;;


                    "tommc")
                        BPortToMMC=1
                    ;;

                    "ota")
                        BOta=1
                    ;;

                    "touch")
                        Bplane=1=1
                    ;;		    

                    *)
                        echo "invalid target $1 to build, only [all|android|kernel|uboot|tommc|ota|touch] supported"
                        usage
                esac
            fi
            shift
        ;;

        "-c")
            shift
            BClean=1
            if [ $# -le 0 ];then
                BCleanAndroid=1
                BCleanKernel=1
                BCleanUBoot=1
            else
                case $1 in 
                    "all")
                        BCleanAndroid=1
                        BCleanKernel=1
                        BCleanUBoot=1
                    ;;

                    "android")
                        BCleanAndroid=1
                    ;;

                    "kernel")
                        BCleanKernel=1
                    ;;

                    "uboot")
                        BCleanUBoot=1
                    ;;

                    *)
                        echo "invalid target $1 to clean, only [all|android|kernel|uboot] supported"
                        usage
                esac
            fi
            shift

        ;;

        *)
            errout "can not recognize arg $1"
            usage
        esac
    done

}

do_make_mbr()
{
    [ $BOta -eq 0 ] || return
    # /dev/sdx1    boot        16MB    vfat
    # /dev/sdx2    system      254MB   ext4
    # create sdx1
    printf "o\np\nn\np\n1\n\n$MMCBootPartSize\nt\n83\np\nw\n" | fdisk $1
    #create sdx2
    printf "p\nn\np\n\n\n\nt\n2\n83\nw\n" | fdisk $1
    # print the partition table
    printf "p\nq\n" | fdisk $1

    sync; sleep 1;

    # format partitions
    echo mkfs.vfat -F 32 -n boot   "$1"1
    mkfs.vfat      -F 32 -n boot   "$1"1
    echo mkfs.ext4 -v -L system    "$1"2
    mkfs.ext4      -v -L system    "$1"2

    sync; sleep 1;

}

do_make_mbr_ota()
{
    # /dev/sdx1 recovery
    [ $BOta -eq 1 ] || return
    #create sdx1
    printf "o\np\nn\np\n\n\n\nt\n83\np\nw\n" | fdisk $1
    # print the partition table
    printf "p\nq\n" | fdisk $1

    sync; sleep 1;

    # format partitions
    echo mkfs.vfat -F 32 -n recovery   "$1"1
    mkfs.vfat      -F 32 -n recovery   "$1"1

    sync; sleep 1;

}

make_mbr ()
{
    echo "================format $MMCDevName======================================="
    [ -e $MMCDevName ] || errout "can not find MMC dev " 

    local INPUT_Y_N=
    echo "are you sure to modify device $SD_DEVICE ,you will lost the data in it."
    echo "please type y to continue:[Y/N]"
    read INPUT_Y_N
    if [ "$INPUT_Y_N" != "y" ] && [ "$INPUT_Y_N" != "Y" ];then
        errout "user canceled..."
    fi

    # kill udevd --daemon
    killall -9 udevd
    umount $MMCDevName[1-7]
    sync ;sleep 1

    # kill /etc/udec/script/CARD_DET
    card_det=`ps|grep CARD_DET|sed 's/^ \+//g'|cut -d\  -f1|head -1`
    kill -9 $card_det
    
    if [ $BOta -eq 0 ];then
        do_make_mbr $1
    else
        do_make_mbr_ota $1
    fi
    echo "================format $MMCDevName done=================================="
}

do_copytoMMC()
{
    umount $MMCDevName[1-7]
    sync ;sleep 1
    [ -d $MMCBootPath ] || mkdir $MMCBootPath
    mount $MMCDevName"1" $MMCBootPath || errout "mount $MMCDevName"1" $MMCBootPath failed"

    [ -d $MMCSystemPath ] || mkdir $MMCSystemPath
    mount $MMCDevName"2" $MMCSystemPath || errout "mount $MMCDevName"2" $MMCSystemPath failed"

    [ -d $AndroidFinalOutputPath ] || errout "dir not exist:$AndroidFinalOutputPath"
    [ -d $KernelFinalOutputPath ] || errout "dir not exist:$KernelFinalOutputPath"

    cp $AndroidFinalOutputPath"/"* $MMCSystemPath -rf || error "cp $AndroidFinalOutputPath"/"* $MMCSystemPath failed"
    cp $KernelFinalOutputPath"/"* $MMCBootPath -rf || error "cp $KernelFinalOutputPath"/"* $MMCSystemPath failed"
}

do_copytoMMC_ota()
{
    umount $MMCDevName[1-7]
    [ -d $MMCRecoveryDir ] || mkdir $MMCRecoveryDir
    mount $MMCDevName"1" $MMCRecoveryDir || errout "mount $MMCDevName"1" $MMCRecoveryDir failed"
    
    [ -d $OTABspPath ] || errout "dir not exist:$OTABspPath"
    cp $OTABspPath $MMCRecoveryDir -rf || error "cp $OTABspPath $MMCRecoveryDir failed"
}

cpToMMC()
{
    echo "================copy files to mmc======================================="
    if [ $BOta -eq 0 ];then
        do_copytoMMC
    else
        do_copytoMMC_ota
    fi

    echo "================copy files to mmc done======================================="

}

OTACopy()
{
    echo "================copy files to ota======================================="
    [ $BOta -eq 1 ] || return
    
    for ((i=0;i<${#OTAbspinst_array[@]};i++))
    do
        [ "${OTAbspinst_array[$i]}" != "" ] || continue
        
        if [ -e ${OTAbspinst_array[$i]} ];then
            cp ${OTAbspinst_array[$i]} $OTABspPath 
        else
            errout "ota:file not exist : ${OTAbspinst_array[$i]}" 2
        fi 
    done
 
    echo "================copy files to ota done==================================="
}

modifyCFBArgs()
{
    echo "=================modifyCFBargs:============="
    [ -e $TouchPlaneARGSFile ] || errout "can not find file $TouchPlaneARGSFile"
    sed -i 's/cbp5850_fb.ko/cbp5850_fb.ko cbpfb_bus=dsi cbpfb_busmode=video cbpfb_dev=nt35590h cbpfb_mode=720x1280@60 cbpfb_bpp=32/g' $TouchPlaneARGSFile
    #sed -n 's/cbp5850_fb.ko/cbp5850_fb.ko cbpfb_bus=dsi cbpfb_busmode=video cbpfb_dev=nt35590h cbpfb_mode=720x1280@60 cbpfb_bpp=32/g' $TouchPlaneARGSFile   
    echo "=================modifyCFBargs done:============="
}

vtcAndroidConfig()
{
    AndroidLocalOutPutPath=$AndroidPath"out/target/product/"$VTCProductName
}

vtcKernelConfig()
{
    VTCKernelConfigName="$VTCProductName"_defconfig
}

vtcUBootConfig()
{
    VTCUBootConfigName="$VTCProductName"boards.cfg
}

vtcBuild()
{
    echo -e "\nbuild product: $VTCProductName"

    local count=0

    for bi in $BBuildKernel $BBuildAndroid $BBuildUBoot $BOta $BPortToMMC
    do
        if [[ $bi -eq 1 ]];then
            count=`expr $count + 1`
            break
        fi
    done

    if [ $count -eq 0 ];then
        echo -e "\n$count targets specified to build"
        usage
    fi

	if [ $BBuildKernel -eq 1 ];then
        vtcKernelConfig
        buildKernel
        cpKernelfile
    fi
 
    if [ $BBuildAndroid -eq 1 ];then
        vtcAndroidConfig
        buildAndroid
        cpAndroidFileSys
    fi

   if [ $BBuildUBoot -eq 1 ];then
        vtcUBootConfig
        buildUBoot
        cpUBootfile
    fi
    
    if [ $Bplane -eq 1 ] ;then
        if [ $BBuildAndroid -ne 1 ];then
            errout "no android path is set,skip modify the touch args" 2
        else
            modifyCFBArgs
        fi
    fi
 
    if [ $BOta -eq 1 ];then
        OTACopy
    fi

    if [ $BPortToMMC -eq 1 ];then
        make_mbr $MMCDevName
        cpToMMC 
    fi
}

cleanAndroid()
{
    echo "=============clean Android============"
    [ -d "$AndroidPath" ] || errout "can not find path : $AndroidPath "

    cd "$AndroidPath"

    [ -d "./out/" ] && rm ./out/ -rf

    cd - >/dev/null 2>&1

    if [ -d $AndroidFinalOutputPath ];then
        rm -rf $AndroidFinalOutputPath 
    fi

    echo "=============clean Android done=========="

}

cleanKernel()
{
    echo "=============clean Kernel ============"
 
    if [ ! -d "$KernelPath" ];then
        errout "can not find path : $KernelPath "
    fi

    cd "$KernelPath"

    make clean CROSS_COMPILE=$CROSS_COMPILE ARCH=arm
    make distclean CROSS_COMPILE=$CROSS_COMPILE ARCH=arm
    make mrproper CROSS_COMPILE=$CROSS_COMPILE ARCH=arm

    cd - >/dev/null 2>&1

    if [ -d $KernelFinalOutputPath ];then
        rm -rf $KernelFinalOutputPath 
    fi

    echo "=============clean Kernel done=========="
}

cleanUBoot()
{
    echo "=============clean uboot============"
    [ -d "$UBootPath" ] || errout "can not find path : $UBootPath "

    cd "$UBootPath"

    make clean CROSS_COMPILE=$CROSS_COMPILE ARCH=arm
    make distclean CROSS_COMPILE=$CROSS_COMPILE ARCH=arm
    make mrproper CROSS_COMPILE=$CROSS_COMPILE ARCH=arm

    cd - >/dev/null 2>&1

    if [ -d $UBootFinalOutputPath ];then
        rm -rf $UBootFinalOutputPath 
    fi

    echo "=============clean uboot done=========="

}

vtcClean()
{
    if [ $BCleanAndroid -eq 1 ];then
        cleanAndroid
    fi

    if [ $BCleanKernel -eq 1 ];then
        cleanKernel
    fi

    if [ $BCleanUBoot -eq 1 ];then
        cleanUBoot
    fi

    if [[ -d $ProductFinalOutputPath &&  (`ls -la $ProductFinalOutputPath | wc -l` -eq 3) ]]; then
        rm -rf $ProductFinalOutputPath
    fi
}

if [ $# -lt 1 ];then
    usage
else 
    parseArgs $*
fi 

if [[ $BClean -eq 1 ]]; then
    vtcClean
else 
    vtcBuild
fi

