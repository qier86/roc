#! /bin/bash

SAVE_PATH="`pwd`/.tag"

usage()
{
	echo "
	"
	echo "Usage: `basename $0` [Dir]..."
	echo " Dir	set the save directory,which default is ${SAVE_PATH}"
	echo "
	"
}

if [ -n "$1" ];then
	SAVE_PATH=$1
fi

if [ -d ${SAVE_PATH} ];then
	echo "error: directroy $SAVE_PATH already exist."
	exit 
fi

echo "create tags into ${SAVE_PATH}"
mkdir ${SAVE_PATH} -p
find . -name "*.h" -o -name "*.c" -o -name "*.cc" > ${SAVE_PATH}/cscope.files
cscope -Rbkq -i ${SAVE_PATH}/cscope.files -f ${SAVE_PATH}/cscope 
ctags -R  --tag-relative=yes -f ${SAVE_PATH}/tags
