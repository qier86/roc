#!/bin/bash

#Warning:
#
#This cript can be only used by VTC Release Version Managers, 
#it aims at setup vtc product developing enviroment, 
#so vtc engineers can build product images which including vtc source code.
#Following actions are executed:
#    1. create symbol links to vtc source including kernel, uboot, android, configs
#    2. Modify Makefile & Kconfig under $(KernelPath)/arch/arm to include vtc kernel source files
#    3. Modify $(AndroidPath)/build/core/product.mk to include vtc android source files
#

#Project variables
AndroidPath=../android_4.2.2_r1/
KernelPath=../kernel_3.4.39/
UBootPath=../uboot_201304/

#VTC variables
VTCTopPath=viatelecom/
VTCSystemSrcPath="$VTCTopPath"system/
VTCKernelSrcPath="$VTCTopPath"kernel/
VTCUBootSrcPath="$VTCTopPath"uboot/
VTCProductRootPath="$VTCTopPath"product/

VTCLinkFile=vtc

env_set() 
{
    #0. Goto path where this script exists
    cd ${0%/*}

    #1. creat symbol links to vtc source
    cd .. && ( [[ -L vtc_build.sh ]] || ln -s "$VTCTopPath"vtc_build.sh vtc_build.sh ) && cd - >/dev/null 2>&1

    cd $AndroidPath && ( [[ -L $VTCLinkFile ]] || ln -s ../$VTCSystemSrcPath $VTCLinkFile ) && cd - >/dev/null 2>&1
    cd "$AndroidPath"device && ( [[ -L $VTCLinkFile ]] || ln -s ../../$VTCProductRootPath $VTCLinkFile ) && cd - >/dev/null 2>&1

    cd $KernelPath && ( [[ -L $VTCLinkFile ]] || ln -s ../$VTCKernelSrcPath $VTCLinkFile ) && cd - >/dev/null 2>&1
    cd $UBootPath && ( [[ -L $VTCLinkFile ]] || ln -s ../$VTCUBootSrcPath $VTCLinkFile ) && cd - >/dev/null 2>&1

    #2. Modify kernel build system
    if [[ -z `grep "vtc/Kconfig" "$KernelPath"arch/arm/Kconfig` ]]; then
        sed -i '$a \
                 \
    source "vtc/Kconfig"' "$KernelPath"arch/arm/Kconfig
    fi

    if [[ -z `grep "vtc/Makefile" "$KernelPath"arch/arm/Makefile` ]]; then
        sed -i '/platdirs :=/a\
                         \
    include $(srctree)/vtc/Makefile' "$KernelPath"arch/arm/Makefile
    fi

    if [[ -z $(grep "find -L \$(if" "$KernelPath"Makefile) ]]; then
        sed -i "s/find \$(if/find -L \$(if/" "$KernelPath"Makefile
    fi


    #3. Modify android build system
    if [[ -z `grep "find -L device" "$AndroidPath"build/core/product.mk` ]]; then
        sed  -i 's\find device\find -L device\' "$AndroidPath"build/core/product.mk 
    fi 
}

env_clear()
{

    #0. Goto path where this script exists
    cd ${0%/*}

    #1. Delete symbol links to vtc source
    ( cd .. && [[ -L vtc_build.sh ]] && rm vtc_build.sh && cd -) >/dev/null 2>&1

    ( cd $AndroidPath && [[ -L $VTCLinkFile ]] && rm $VTCLinkFile && cd - ) >/dev/null 2>&1
    ( cd "$AndroidPath"device && [[ -L $VTCLinkFile ]] && rm $VTCLinkFile && cd - ) >/dev/null 2>&1

    ( cd $KernelPath && [[ -L $VTCLinkFile ]] && rm $VTCLinkFile && cd - ) >/dev/null 2>&1
    ( cd $UBootPath && [[ -L $VTCLinkFile ]] && rm $VTCLinkFile && cd - ) >/dev/null 2>&1

    #2. Restore modified kernel build system
    cd $KernelPath
    if [[ ! -z `grep "vtc/Kconfig" arch/arm/Kconfig` ]]; then
        git checkout arch/arm/Kconfig
    fi

    if [[ ! -z `grep "vtc/Makefile" arch/arm/Makefile` ]]; then
        git checkout arch/arm/Makefile
    fi

    if [[ ! -z $(grep "find -L \$(if" Makefile) ]]; then
        git checkout Makefile
    fi
    cd - >/dev/null 2>&1

    #3. Restore modified android build system
    cd $AndroidPath"build"
    if [[ ! -z `grep "find -L device" core/product.mk` ]]; then
        git checkout core/product.mk 
    fi 
    cd - >/dev/null 2>&1

}

usage()
{
    echo  "Usage: `basename $0` [option]...              "
    echo  "Option:                                       "
    echo  "    -s: setup vtc build enviroment            "
    echo  "    -c: clear vtc build enviroment            "
    echo  "    -h: display usage help                    "
    echo  "                                              "
    echo  "Notice: default option is -s if no user input "
}

if [ $# -le 0 ]; then
    env_set
else
    case $1 in 
        "-s")
            env_set
        ;;


        "-c")
            env_clear
        ;;

        "-h")
            usage
        ;;

        *)
            echo "Unknown command option: $1"
            usage
        ;;
    esac
fi

exit 0
