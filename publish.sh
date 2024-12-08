#!/bin/sh

#MOD_NAME=axdriver
#MOD_NAME=taskctx
#MOD_NAME=ext2fs
#MOD_NAME=axfs_vfs
#MOD_NAME=axfs_devfs
#MOD_NAME=axerrno
MOD_NAME=axlog2

#MOD_NAME=early_console
#MOD_NAME=axlog2
#MOD_NAME=axhal
#MOD_NAME=user_stack
#MOD_NAME=driver_block
#MOD_NAME=driver_virtio
#MOD_NAME=page_table

#MOD_NAME=axmount
#MOD_NAME=mutex
#MOD_NAME=axalloc
#MOD_NAME=fstree

#MOD_NAME=run_queue
#MOD_NAME=mm
#MOD_NAME=mmap
#MOD_NAME=fileops
#MOD_NAME=fork
#MOD_NAME=axfs_ramfs
#MOD_NAME=axdtb
#MOD_NAME=bprm_loader
#MOD_NAME=exec

PUB_PATH=/tmp/pub_path

#rm -rf $PUB_PATH
mkdir -p $PUB_PATH

git clone git@github.com:shilei-massclouds/$MOD_NAME $PUB_PATH/$MOD_NAME

cp -rf ./$MOD_NAME/* $PUB_PATH/$MOD_NAME/
