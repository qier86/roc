/*
 * nvram.c
 *
 * VIA nvram driver for Linux
 *
 * Copyright (C) 2013 VIA TELECOM Corporation, Inc.
 * Author: VIA TELECOM Corporation, Inc.
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THIS PACKAGE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.  */
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/mtd/mtd.h>
#include <linux/slab.h>
#include <linux/irq.h>
#include <linux/wakelock.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>

static unsigned long nvram_debug = 1;
#define nvram_version "0.0.1"
#define DPRT(fmt, arg...)  do{ \
    if(nvram_debug) \
        printk("[NVRAM %s:%d] " fmt,  __FUNCTION__, __LINE__, ##arg); \
    }while(0)
    
#define PRT(fmt, arg...)  printk("[NVRAM %s:%d] " fmt, __FUNCTION__, __LINE__, ##arg)
#define NVRAM_PARTITION_LABEL "nvram"
static struct workqueue_struct *nvram_work_queue;

struct nvram_file {
    u32 size;
    u32 page;
    u32 seqnum;
    u32 uid;
    u32 gid;
    u32 mode;
    u32 len;
    char path[0];
};

struct nvram_file_node {
    struct list_head node;
    struct nvram_file pfile[0];
};

#define PAGE_MAGIC (0x7A6B)
struct nvram_page_header {
    u16 magic;
    u16 next;
    u32 seqnum;
};

#define HEADER_MAGIC (0xEDCB9876) 
struct nvram_header {
    u32 magic;
    u32 checksum;
    u32 seqnum;
    u32 count;
    struct nvram_file file[0];
};

struct nvram_collect_link {
    u16 src;
    u16 dst;
};

#define COLLECT_MAGIC (0xABCD1234)
struct nvram_collect_header {
    u32 magic;
    u32 checksum;
    struct nvram_collect_link ltable[0];
};

enum BLOCK_TYPE{
    BLOCK_HEADER_0 = 0,
    BLOCK_HEADER_1 = 1,
    BLOCK_COLLECT,
    BLOCK_DATA_BASE,
    BLOCK_TYPE_COUNT
};

struct nvram_handle {
    u32 *bbt;//bad block bit map table
    u32 *fpt; //free page bit map table
    u32 *gpt; //garbage page bit map table
    u32 index;//the block used to construct nvram header
    u32 blocks;//the number of block
    u32 seqnum;
    u32 pages;// the number of page
    u32 rblock[BLOCK_TYPE_COUNT];//the reserved block for special use
    u32 pb; //page number in one block
    u32 block_size; //block size
    u32 block_shift;
    u32 block_mask;
    u32 page_size;//page size
    u32 page_shift;
    u32 page_mask;
    u32 partition_size;//nvram partition size
    struct mutex mlock;
    struct mtd_info *mtd;
    struct nvram_header header;
    struct nvram_collect_header *pchead;
    u32 *seq_table;
    struct list_head file_restore_list;
    u8 *buffer;
};

static struct nvram_handle nvram_hd;
static struct nvram_handle *phd = &nvram_hd;

static void nvram_set_bit(u32 *table, u32 offset, u32 v)
{
    u32 flag = 1;

    if(v){
        flag = flag << (offset%32);
        table[offset/32] |= flag;
    }else{
        flag = ~(flag << (offset%32));
        table[offset/32] &= flag;
    }
}

static u32 nvram_get_bit(u32 *table, u32 offset)
{
    u32 flag;

    flag = 1 << (offset%32);
    return !!(table[offset/32] & flag);
}

static inline void set_bbt(u32 block)
{
    BUG_ON((!phd->bbt) || (block >= phd->blocks));
    nvram_set_bit(phd->bbt, block, 1);
}

static inline void clear_fpt(u32 page)
{
    BUG_ON((!phd->fpt) || (page >= phd->pages));
    nvram_set_bit(phd->fpt, page, 0);
}

static inline u32 get_bbt(u32 block)
{
    BUG_ON((!phd->bbt) || (block >= phd->blocks));
    return nvram_get_bit(phd->bbt, block);
}

static inline void set_fpt(u32 page)
{
    BUG_ON((!phd->fpt) || (page >= phd->pages));
    nvram_set_bit(phd->fpt, page, 1);
}

static inline u32 get_fpt(u32 page)
{
    BUG_ON((!phd->fpt) || (page >= phd->pages));
    return nvram_get_bit(phd->fpt, page);
}

static inline void set_gpt(u32 page)
{
    BUG_ON((!phd->gpt) || (page >= phd->pages));
    nvram_set_bit(phd->gpt, page, 1);
}

static inline void clear_gpt(u32 page)
{
    BUG_ON((!phd->gpt) || (page >= phd->pages));
    nvram_set_bit(phd->gpt, page, 0);
}

static inline u32 get_gpt(u32 page)
{
    BUG_ON((!phd->gpt) || (page >= phd->pages));
    return nvram_get_bit(phd->gpt, page);
}

#define NVRAM_INVALID_BLOCK (0xFFFFFFFF)
static u32 nvram_block_offset(u32 offset)
{
	u32 logic_block = offset>>(phd->block_shift);
	u32 phy_block;
	u32 good_block = 0;

	for (phy_block = 0; phy_block < phd->blocks; phy_block++) {
		if (!get_bbt(phy_block))
			good_block++;
		if (good_block == (logic_block + 1))
			break;
	}

	if (good_block != (logic_block + 1))
		return NVRAM_INVALID_BLOCK;

	return offset + ((phy_block-logic_block)<<phd->block_shift);
}

static inline u32 get_free_page(void)
{
    u32 i = phd->rblock[BLOCK_DATA_BASE] >> phd->page_shift;
    for(; i < phd->pages; i++){
        if(get_fpt(i)){
            return i;
        }
    }

    return 0;
}

static inline u32 sum_bad_block(void)
{
    u32 sum = 0, i;
    for(i = 0; i < phd->blocks; i++){
        if(get_bbt(i)){
            sum ++;
        }
    }

    return sum;
}

static inline u32 sum_free_page(void)
{
    u32 sum = 0;
    u32 i = phd->rblock[BLOCK_DATA_BASE] >> phd->page_shift;
    for(; i < phd->pages; i++){
        if(get_fpt(i)){
            sum ++;
        }
    }

    return sum;
}

static inline u32 sum_garbage_page(void)
{
    u32 sum = 0;
    u32 i = phd->rblock[BLOCK_DATA_BASE] >> phd->page_shift;
    for(; i < phd->pages; i++){
        if(get_gpt(i)){
            sum ++;
        }
    }

    return sum;
}

static int nvram_phy_read(u32 from, u32 len, u32 *retlen, u8 *buf)
{
    int ret = 0;

    if(from >= phd->partition_size){
        PRT("Error address 0x%x to phy read, partiton size is 0x%x.\n", from, phd->partition_size);
        return -EINVAL;
    }

    if(phd->mtd)
        //ret = phd->mtd->read(phd->mtd, from, len, retlen, buf);
        ret = mtd_read(phd->mtd, from, len, retlen, buf);
    else
        ret = -ENODEV;

    return ret;
}

static void nvram_erase_callback(struct erase_info *done)
{
    wait_queue_head_t *wait_q = (wait_queue_head_t *) done->priv;
    wake_up(wait_q);
}

static void nvram_erase_all(void)
{
    struct erase_info erase;
    DECLARE_WAITQUEUE(wait, current);
    wait_queue_head_t wait_q;
    int rc;
    u32 i;

    init_waitqueue_head(&wait_q);
    erase.mtd = phd->mtd;
    erase.callback = nvram_erase_callback;
    erase.len = phd->block_size;
    erase.priv = (u_long)&wait_q;
    for (i = 0; i < phd->mtd->size; i += phd->mtd->erasesize) {
        erase.addr = i;
        set_current_state(TASK_INTERRUPTIBLE);
        add_wait_queue(&wait_q, &wait);

        if (get_bbt(i >> phd->block_shift)) {
            PRT("Skipping erase of bad block %u @%x\n", i >> phd->block_shift, i);
            set_current_state(TASK_RUNNING);
            remove_wait_queue(&wait_q, &wait);
            continue;
        }

        //rc = phd->mtd->erase(phd->mtd, &erase);
        rc = mtd_erase(phd->mtd, &erase);
        if (rc) {
            set_current_state(TASK_RUNNING);
            remove_wait_queue(&wait_q, &wait);
            PRT("Erase of block %u@0x%x, 0x%x failed\n", i >> phd->block_shift, i, phd->block_size);
            if (rc == -EIO) {
                //if (phd->mtd->block_markbad(phd->mtd, erase.addr)) {
                if (mtd_block_markbad(phd->mtd, erase.addr)) {
                    PRT("Fail to  marking block %u@%x bad\n", i >> phd->block_shift, i);
                    goto out;
                }
                PRT("Marked a bad block %u@%x\n", i >> phd->block_shift, i);
                set_bbt(i >> phd->block_shift);
                continue;
            }
            goto out;
        }
        schedule();
        remove_wait_queue(&wait_q, &wait);
    }
    PRT("%s partition erased\n", NVRAM_PARTITION_LABEL);
out:
    return;
}

static int nvram_erase_block(u32 offset)
{
    u32 block = offset >> (phd->block_shift); 
    struct erase_info erase;
    int ret = 0;

    if(offset >= phd->partition_size){
        PRT("Error address %u to block erase, partiton size is %u.\n", offset, phd->partition_size);
        ret = -EINVAL;
        goto _end;
    }
    erase.mtd = phd->mtd;
    erase.callback = NULL;
    erase.len = phd->block_size;
    erase.priv = 0;
    erase.addr = block << (phd->block_shift);

    if (get_bbt(block)) {
        PRT("Skipping erase of bad block %u@0x%x\n", block, offset);
        ret = -EINVAL;
        goto _end ;
    }

    //ret = phd->mtd->erase(phd->mtd, &erase);
    ret = mtd_erase(phd->mtd, &erase);
    if (ret) {
        PRT("Erase of block %u, address 0x%x, size 0x%x failed\n", block, offset, phd->block_size);
        if (ret == -EIO) {
            if (mtd_block_markbad(phd->mtd, erase.addr)) {
                PRT("Fail to  marking block %u bad\n", block);
                goto _end;
            }
            PRT("Marked a bad block %u@0x%x\n", block, offset);
            set_bbt(block);
        }
        goto _end;
    }

    DPRT("block %u  erased\n", block);
_end:
    return ret;
}

static int nvram_phy_write(u32 to, u32 len, u32 *retlen, const u8 *buf)
{
    int ret = 0;
    if(to >= phd->partition_size){
        PRT("Error address %u to phy write, partiton size is %u.\n", to, phd->partition_size);
        return -EINVAL;
    }

    if(phd->mtd)
        //ret = phd->mtd->write(phd->mtd, to, len, retlen, buf);
        ret = mtd_write(phd->mtd, to, len, retlen, buf);
    else
        ret = -ENODEV;

    return ret;
}

static u32 nvram_checksum(u8 *data, int len)
{
    u32 checksum = 0;

    while(len > 0){
        len--;
        checksum += data[len];
    }
    return checksum;
}

static int nvram_valid_seqnum(u32 seqnum)
{
    int low, mid, high;

    if(NULL == phd->seq_table){
        return 1;
    }

    if(phd->header.count <= 0){
        return 1;
    }

    low = 0;
    mid = 0;
    high = (int)(phd->header.count - 1);
    while(low <= high){
        mid = (low + high) / 2;
        if(phd->seq_table[mid] == seqnum){
            return 1;
        }else if(phd->seq_table[mid] > seqnum){
            high = mid - 1;
        }else{
            low = mid + 1;
        }
    }
    return 0;
}

static int nvram_seqnum_table_create(void)
{
    int i = 0, j = 0;
    u32 tmp;
    struct nvram_file_node *pfnode = NULL;

    if(phd->seq_table){
        kfree(phd->seq_table);
        phd->seq_table = NULL;
    }

    if(phd->header.count <= 0){
        return 0;    
    }

    phd->seq_table = (u32 *)kzalloc(phd->header.count * sizeof(u32), GFP_KERNEL);
    if(phd->seq_table == NULL){
        return -ENOMEM;
    }
    list_for_each_entry(pfnode, &phd->file_restore_list, node) {
        DPRT("%d) path:%s, seqnum:%u, size:%u.\n", i, pfnode->pfile->path, pfnode->pfile->seqnum, pfnode->pfile->size);
        phd->seq_table[i] = pfnode->pfile->seqnum;
        i++;
    }
    
    //bubble sort the file seqnum low to high
    for(i = 0; i < phd->header.count; i++){
        for(j = 1; j < (phd->header.count - i); j++){
            if(phd->seq_table[ j - 1 ] > phd->seq_table[ j ]){
                tmp = phd->seq_table[ j - 1 ];
                phd->seq_table[ j - 1 ] = phd->seq_table[ j ];
                phd->seq_table[ j ] = tmp;
            }
        }
    }

    return 0;
}

static void nvram_header_save(void)
{
    int ret = 0;
    u32 rlen = 0, offset = 0;
    u32 checksum = 0;
    u32 count = 0, pages = 0, nsize = 0, psize = 0;
    u8 *pbuf = NULL, *buffer = NULL;
    struct nvram_header *phead = NULL;
    struct nvram_file *pfile = NULL;
    struct nvram_file_node *pfnode = NULL;
    struct list_head *plist = NULL;

    buffer = phd->buffer;
    memset(buffer, 0, phd->page_size);
    pbuf = buffer;
    phead = &phd->header;
    plist = &phd->file_restore_list;

    //step1: erase the header block and prepare the struct nvram_header 
    phd->index = !phd->index;
    ret = nvram_erase_block(phd->rblock[phd->index]);
    if(ret < 0){
        PRT("Fail to erase nvram header block %u.\n", phd->index);
        goto _end;
    }
    list_for_each_entry(pfnode, plist, node) {
       count++;
       rlen = 0;
       //ignore the padding length in checksum
       if((pfnode->pfile->len) > (strlen(pfnode->pfile->path) + 1)){
             rlen = pfnode->pfile->len;
             pfnode->pfile->len = strlen(pfnode->pfile->path) + 1;
             DPRT("ignore pad len checksum 0x%x.\n", rlen - pfnode->pfile->len);
       }
       checksum += nvram_checksum((u8 *)pfnode->pfile, sizeof(struct nvram_file));
       checksum += nvram_checksum((u8 *)pfnode->pfile->path, pfnode->pfile->len);
       if(rlen){
             pfnode->pfile->len = rlen;
       }
    }
    rlen = 0;
    phead->magic = HEADER_MAGIC;
    phd->seqnum++;
    phead->seqnum = phd->seqnum;
    phead->count = count;
    checksum += nvram_checksum((u8 *)&phead->seqnum, sizeof(u32));
    checksum += nvram_checksum((u8 *)&phead->count, sizeof(u32));
    phead->checksum = checksum;
    memcpy(pbuf, phead, sizeof(struct nvram_header));

    //step 2: save the each file into header block
    pfile = NULL; //the previous file point in buffer
    pages = 0;
    offset = sizeof(struct nvram_header);
    pbuf = buffer + offset;
    list_for_each_entry(pfnode, plist, node) {        
        if(pages >= phd->pb){
            PRT("Error: no space in block %u to save file node %s.\n", phd->index, pfile->path);
            ret = -ENOSPC;
            goto _end;
        }

        nsize = pfnode->pfile->len + sizeof(struct nvram_file);
        psize = phd->page_size - offset;
        //the free space in the page is not enough to save the file node 
        if(nsize > psize){
          //save file node page by page, no file node would be saved between tow pages
            DPRT("pad %u into file %s align one page, offset:%u.\n", psize, pfile->path, offset);
            pfile->len += psize; //pad the length to align one page
            ret = nvram_phy_write(phd->rblock[phd->index] + (pages << phd->page_shift), phd->page_size, &rlen, buffer);
            if(rlen != phd->page_size){
                PRT("Fail to write buffer into page %u, ret=%d, rlen=%u.\n", pages, ret, rlen);
                ret = -EIO;
                goto _end;
            }
            DPRT("write buffer into page %u.\n", pages);
            pages++;
            offset = 0;
            memset(buffer, 0, phd->page_size);
            pbuf = buffer;
        }

         memcpy(pbuf, (u8 *)pfnode->pfile, nsize);
         pfile = (struct nvram_file *)(pbuf);
         offset += nsize;
         pbuf = buffer + offset;
         DPRT("cache file %s into page %u buffer, size:%u, offset;%u.\n", pfile->path, pages, nsize, offset);
    }

    //write last page buffer
    if(offset > 0){
         ret = nvram_phy_write(phd->rblock[phd->index] + (pages << phd->page_shift), phd->page_size, &rlen, buffer);
         if(rlen != phd->page_size){
            PRT("Fail to write buffer into page %u.\n", pages);
            ret = -EIO;
            goto _end;
         }
         DPRT("write buffer into page %u block %u.\n", pages, phd->rblock[phd->index] >> phd->block_shift);
    }
_end:
    if(ret < 0){
        phd->index = !phd->index;
    }
    return ;
}

static void nvram_header_destroy(void)
{
    struct nvram_file_node *pfnode = NULL, *pftmp = NULL;
    struct list_head *plist = &(phd->file_restore_list);

    list_for_each_entry_safe(pfnode, pftmp, plist, node) {
        list_del(&pfnode->node);
        kfree(pfnode);
    }
    if(phd->seq_table){
        kfree(phd->seq_table);
        phd->seq_table = NULL;
    }
    INIT_LIST_HEAD(plist);
    memset(&phd->header, 0, sizeof(struct nvram_header));
}

static int nvram_header_construct(u32 index)
{
    int ret = 0;
    u32 rlen = 0, offset = 0;
    u32 checksum = 0;
    u32 count = 0, pages = 0;
    u8 *pbuf = NULL, *buffer = phd->buffer;
    struct nvram_header *phead = NULL;
    struct nvram_file nfile;
    struct nvram_file_node *pfnode = NULL;
    struct list_head *plist = NULL;

    //step 1: parse the struct nvram_header from first page in header block
    if(index > BLOCK_HEADER_1){
        PRT("Invalid nvram header index %u.\n", index);
        ret = -EINVAL;
        goto _end;
    }
    buffer = memset(buffer, 0, phd->page_size);
    phead = &phd->header;
    memset(phead, 0, sizeof(struct nvram_header));
    plist = &phd->file_restore_list;
    INIT_LIST_HEAD(plist);
    offset = 0;
    pages = 0;
    pbuf = buffer;
    //copy first page from nvram to memory, and parse the datas to construct header and file node
    ret = nvram_phy_read(phd->rblock[index], phd->page_size, &rlen, pbuf);
    if (rlen != phd->page_size){
        ret = -EIO;
        PRT("Fail to read  page %u in nvram header %u.\n", pages, index);
        goto _end;
    }

    //construct and check the struct nvram header
    memcpy(phead, pbuf, sizeof(struct nvram_header));
    offset += sizeof(struct nvram_header);
    pbuf = buffer + offset;
    DPRT("magic:0x%x, checksum:%u, seqnum:%u, count:%u.\n", phead->magic, phead->checksum, phead->seqnum, phead->count);

    //step 2: parse the each file in header
    if(phead->magic != HEADER_MAGIC){ //error nvram header magic
        ret = -ENODATA;
        PRT("Invalid header %u magic 0x%x not equal to 0x%x.\n ", index, phead->magic, HEADER_MAGIC);
        goto _end;
    }else if(phead->count == 0){//no file node
        checksum = nvram_checksum((u8 *)&phead->seqnum, sizeof(struct nvram_header) - 8);
        if(checksum != phead->checksum){
            PRT("Invalid header(count=%u) %u checksum 0x%8x not equal to 0x%8x.\n ", phead->count, index, phead->checksum, checksum);
            ret = -ENODATA;
            goto _end;
        }
    }else{//need parse file nodes
        count = 0;
        while(count < phead->count){
            //parse file node page by page, no file node would be saved between tow pages
            if(offset >= phd->page_size){
                pages++;
                if(pages >= phd->pb){
                    PRT("Error: the parsed file number %u in one block is less than %u described in header %u.\n", \
                        count, phead->count, index);
                    ret = -EINVAL;
                    goto _end;
                }
                ret = nvram_phy_read(phd->rblock[index] + (pages << phd->page_shift), phd->page_size, &rlen, buffer);
                if (rlen != phd->page_size){
                    ret = -EIO;
                    PRT("Fail to read page %u in nvram header %u.\n", pages, index);
                    goto _end;
                }
                offset = 0;
                pbuf = buffer;
            }
            memcpy(&nfile, pbuf, sizeof(struct nvram_file));
            DPRT("page:%u, offset:%u\n", pages, offset);
            if(0 == nfile.len || nfile.len > (phd->page_size - offset - sizeof(sizeof(struct nvram_file)))){
                PRT("Invalid node len(%u), remain(%u), (page(%u) - offset(%u) - nfile(%u)).\n", \
                       nfile.len, (phd->page_size - offset - sizeof(sizeof(struct nvram_file))), \
                       phd->page_size, offset, sizeof(struct nvram_file));
                ret = -EINVAL;
                goto _end;
            }
            pfnode = kzalloc(sizeof(struct nvram_file_node) + sizeof(struct nvram_file) + nfile.len, GFP_KERNEL);
            if(NULL == pfnode){
                PRT("Fail to kzalloc nvram file node.\n");
                ret = -ENOMEM;
                goto _end;
            }
            memcpy(pfnode->pfile, pbuf, sizeof(struct nvram_file) + nfile.len);
            offset = offset + sizeof(struct nvram_file) + nfile.len;
            pbuf = buffer + offset;
            list_add_tail(&pfnode->node, plist);
            DPRT("parse header%u %u[%u]: size=%u, page=%u, seqnum=%u, uid=%u, gid=%u, mode=%u, len=%u, path=%s.\n", \
                  phd->index, count, phead->count, pfnode->pfile->size, pfnode->pfile->page,  pfnode->pfile->seqnum, \
                   pfnode->pfile->uid,  pfnode->pfile->gid,  pfnode->pfile->mode,  pfnode->pfile->len,  pfnode->pfile->path);
            count ++;
            pfnode = NULL;
        }

        //step 3: check the checksum
        checksum = nvram_checksum((u8 *)&phead->seqnum, sizeof(struct nvram_header) - 8);
        list_for_each_entry(pfnode, plist, node) {
            rlen = 0;
            if(pfnode->pfile->len > (strlen(pfnode->pfile->path) + 1)){
                rlen = pfnode->pfile->len;
                pfnode->pfile->len = strlen(pfnode->pfile->path) + 1;
                DPRT("ignore pad len checksum 0x%x.\n", rlen - pfnode->pfile->len);
            }
            checksum += nvram_checksum((u8 *)pfnode->pfile, sizeof(struct nvram_file) + pfnode->pfile->len);
            if(rlen){
                pfnode->pfile->len = rlen;
            }
        }

        if(checksum != phead->checksum){
             PRT("Invalid header(count=%u) %u checksum 0x%8x not equal to 0x%8x.\n ", phead->count, index, phead->checksum, checksum);
             ret = -ENODATA;
             goto _end;
        }
    }
    DPRT("Success to construct nvram header %u.\n", index);
_end:
    if(ret < 0){
        DPRT("Fail to construct  nvram header %u.\n", index);
        nvram_header_destroy();
    }
    return ret;
}

static int nvram_header_init(void)
{
    int ret = 0;
    u32 rlen = 0;
    u32 max;
    struct nvram_header *phead = NULL;
    struct nvram_header h0, h1;

    //step 1: select the bigger seqnum between header 0 and header 1
    ret = nvram_phy_read(phd->rblock[BLOCK_HEADER_0], sizeof(struct nvram_header), &rlen, (u8 *)&h0);
    if (rlen != sizeof(struct nvram_header)){
        ret = -EIO;
        PRT("Fail to read nvram header %d ret = %d.\n", BLOCK_HEADER_0, ret);
        goto _end;
    }

    ret = nvram_phy_read(phd->rblock[BLOCK_HEADER_1], sizeof(struct nvram_header), &rlen, (u8 *)&h1);
    if (rlen != sizeof(struct nvram_header)){
        ret = -EIO;
        PRT("Fail to read nvram header %d ret = %d.\n", BLOCK_HEADER_1, ret);
        goto _end;
    }

    phead = &phd->header;
    DPRT("ph0.seqnum = %u, ph1.seqnum=%u\n", h0.seqnum, h1.seqnum);
    if(h0.seqnum > h1.seqnum){
        phd->index = BLOCK_HEADER_0;
    }else{
        phd->index = BLOCK_HEADER_1;
    }

    //step 2: construct the nvram header acordding to the bigger seqnum
    ret = nvram_header_construct(phd->index);
    if(ret < 0){
        DPRT("fail to construct nvram header from block %u, try another.\n", phd->index);
        phd->index = !phd->index;
        ret = nvram_header_construct(phd->index);
        if(ret < 0){
            PRT("Fail to construct nvram header from two header block, try to erase nvram.\n");
            nvram_erase_all( );         
            //double save to init the block of BLOCK_HEADER_0 and BLOCK_HEADER_1
            nvram_header_save();
            nvram_header_save();
        }else{//get a good nvram header
            DPRT("backup the good header into another block.\n");
            nvram_header_save(); // backup the good one
        }
    }

    //step 3: create a seqnum table and scan all the pages in partiton to create fpt and gpt
    ret = nvram_seqnum_table_create();
    if(ret < 0){
        PRT("fail to create file seqnum table.\n");
        goto _end;
    }

    //step 4: set the seqnum seed to be max + 1
    max = phd->seqnum;
    if(max < phead->seqnum){
        max = phead->seqnum;
    }
    if(phd->seq_table && max < phd->seq_table[phead->count -1]){
        max = phd->seq_table[phead->count -1];
    }
    phd->seqnum = max + 1;
    DPRT("Get good nvram header from block %u, file count is %u, max seqnum is %u.\n", phd->index, phead->count, phd->seqnum);
  
_end:
    return ret;
}

static int nvram_bitmaps_create(void)
{
    int ret = 0;
    u32 i, rlen, page;
    u32 tsize;
    struct nvram_page_header ph;

    //alloc bit maps
    tsize = (phd->blocks + 32)/32;
    phd->bbt = kzalloc(tsize*4, GFP_KERNEL);
    if(NULL == phd->bbt){
        PRT("Fail to alloc bbt.\n");
        ret = -ENOMEM;
        goto _end;
    }

    tsize = (phd->pages + 32)/32;
    phd->fpt = kzalloc(tsize*4, GFP_KERNEL);
    if(NULL == phd->fpt){
        PRT("Fail to alloc fpt.\n");
        ret = -ENOMEM;
        goto _end;
    }

    tsize = (phd->pages + 32)/32;
    phd->gpt = kzalloc(tsize*4, GFP_KERNEL);
    if(NULL == phd->gpt){
        PRT("Fail to alloc gpt.\n");
        ret = -ENOMEM;
        goto _end;
    }

    //mark the bit maps
    for (i = 0; i < phd->blocks; i++) {
        //if (phd->mtd->block_isbad(phd->mtd, i << phd->block_shift)){
        if (mtd_block_isbad(phd->mtd, i << phd->block_shift)){
            set_bbt(i);
        }
    }

    phd->rblock[BLOCK_HEADER_0] = nvram_block_offset(BLOCK_HEADER_0 << phd->block_shift);
    phd->rblock[BLOCK_HEADER_1] = nvram_block_offset(BLOCK_HEADER_1 << phd->block_shift);
    phd->rblock[BLOCK_COLLECT] = nvram_block_offset(BLOCK_COLLECT << phd->block_shift);
    phd->rblock[BLOCK_DATA_BASE] = nvram_block_offset(BLOCK_DATA_BASE << phd->block_shift);
 
    ret = nvram_header_init();
    if(ret < 0){
        PRT("Fail to init nvram header.\n");
        goto _end;
    }

    page = phd->rblock[BLOCK_DATA_BASE] >> phd->page_shift;
    while(page < phd->pages){
        //if bab block, skip it
        if(get_bbt(page / phd->pb)){
            page += phd->pb;
            continue;
        }
        ret = nvram_phy_read(page << phd->page_shift, sizeof(struct nvram_page_header), &rlen, (u8 *)&ph);
        if (rlen != sizeof(struct nvram_page_header)){
            ret = -EIO;
            PRT("Fail to read nvram page %d header.\n", page);
            goto _end;
        }

        if(PAGE_MAGIC == ph.magic){
            if(!nvram_valid_seqnum(ph.seqnum)){
                set_gpt(page);
            }
        }else{
            set_fpt(page);
        }
        page++;
    }

_end:
    if(ret < 0){
        if(phd->bbt){
            kfree(phd->bbt);
            phd->bbt = NULL;
        }

        if(phd->fpt){
            kfree(phd->fpt);
            phd->fpt = NULL;
        }

        if(phd->gpt){
            kfree(phd->gpt);
            phd->gpt = NULL;
        }
    }

    return ret;
}

static u32 nvram_collect_swap(struct nvram_collect_header *phead)
{
    int ret = 0;
    u32 i = 0, rlen = 0, free = 0;
    struct nvram_collect_link *plink = phead->ltable;
    u32 gblock = 0, hpage = 0;

    ret = nvram_erase_block(phd->rblock[BLOCK_COLLECT]);
    if(ret < 0){
        ret = -EIO;
        PRT("Fail to erase the colloct block %u.\n", phd->rblock[BLOCK_COLLECT] >> phd->block_size);
        goto _end;
    }

    //step 1: copy the file pages according to the link table 
    for(i = 0; i < phd->pb; i++){
        if(plink[i].dst && plink[i].src){
            ret = nvram_phy_read(plink[i].src << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to read src page %u.\n", plink[i].src);
                goto _end;
            }
            rlen = 0;
            ret = nvram_phy_write(plink[i].dst << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to write dst page %u.\n", plink[i].dst);
                goto _end;
            }

            if(0 == gblock){
                gblock = plink[i].src >> (phd->block_shift - phd->page_shift);            
            }
            DPRT("copy from src %u to dst %u.\n", plink[i].src, plink[i].dst);
        }
    }

    //step 2: save the collect header
    phead->magic = COLLECT_MAGIC;
    phead->checksum = nvram_checksum((u8 *)plink, phd->pb * sizeof(struct nvram_collect_link));
    memset(phd->buffer, 0, phd->page_size);
    memcpy(phd->buffer, phead, sizeof(struct nvram_collect_header) + (phd->pb * sizeof(struct nvram_collect_link)));
    //write into last page of collect block
    hpage = phd->rblock[BLOCK_COLLECT] + ((phd->pb - 1) << phd->page_shift);
    ret = nvram_phy_write(hpage, phd->page_size, &rlen, phd->buffer);
    if(rlen != phd->page_size){
        ret = -EIO;
        PRT("Fail to write collect header page %u.\n", hpage >> phd->page_shift);
        goto _end;
    }
    
    //step 3: erase the garbage block
    if(gblock < BLOCK_DATA_BASE){
        PRT("Error garbage block number %u.\n", gblock);
        for(i = 0; i < phd->pb; i++){
            PRT("%u) src(%u) -> dst(%u).\n", i, plink[i].src, plink[i].dst);
        }
        ret = -EINVAL;
        goto _end;
    }
    ret = nvram_erase_block(gblock << phd->block_shift);
    if(ret < 0){
        ret = -EIO;
        PRT("Fail to erase the garbage block %u.\n", gblock);
        goto _end;
    }
    
    //step 4: copy the file pages according to the link table 
    for(i = 0; i < phd->pb; i++){
        if(plink[i].dst && plink[i].src){
            ret = nvram_phy_read(plink[i].dst << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to read dst page %u.\n", plink[i].dst);
                goto _end;
            }
            rlen = 0;
            ret = nvram_phy_write(plink[i].src << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to write src page %u.\n", plink[i].src);
                goto _end;
            }

            DPRT("copy from dst %u to src %u.\n", plink[i].dst, plink[i].src);
        }
    }

    //step 5: clear the gabage bit map and set free page bit map 
    for(i = 0; i < phd->pb; i++){
        if(get_gpt(plink[i].src)){
            //garbage page
            DPRT("Collect grabage page %u.\n", plink[i].src);
            set_fpt(plink[i].src);
            free ++;
        }else if(get_fpt(plink[i].src)){
            //free page
            set_fpt(plink[i].src);
        }else{
            //data page
            clear_fpt(plink[i].src);
        }
        clear_gpt(plink[i].src);
    }
    
_end:
    //step 6: erase collect block
    ret = nvram_erase_block(phd->rblock[BLOCK_COLLECT]);
    if(ret < 0){
        ret = -EIO;
        PRT("Fail to erase the colloct block %u.\n", phd->rblock[BLOCK_COLLECT] >> phd->block_shift);
    }
    return free;
}

static int nvram_collect_check(void)
{
    int ret = 0;
    u32 i = 0, rlen = 0, checksum = 0;
    struct nvram_collect_header *phead = phd->pchead;
    struct nvram_collect_link *plink = phead->ltable;
    u32 gblock = 0, hpage = 0;

    //step 1: get and check the header from the last page of collect block
    hpage = phd->rblock[BLOCK_COLLECT] + ((phd->pb - 1) << phd->page_shift);
    ret = nvram_phy_read(hpage, phd->page_size, &rlen, phd->buffer);
    if(rlen != phd->page_size){
        ret = -EIO;
        PRT("Fail to read collect header page %u.\n", hpage >> phd->page_shift);
        goto _end;
    }
    memcpy(phead, phd->buffer, sizeof(struct nvram_collect_header) + (phd->pb * sizeof(struct nvram_collect_link)));
    
    if(phead->magic != COLLECT_MAGIC){
        ret = 0;
        DPRT("No collect header, error magic 0x%x.\n", phead->magic);
        goto _end;
    }
    
    checksum = nvram_checksum((u8 *)plink, phd->pb * sizeof(struct nvram_collect_link));
    if(phead->checksum != checksum){
        ret = 0;
        DPRT("No collect header, error checksum %u.\n", phead->checksum);
        goto _end;
    }

    PRT("Warnning: unfinished garbage collection action has been detected.\n");

    //step 2: erase the garbage block
    for(i = 0; i < phd->pb; i++){
        if(plink[i].src && plink[i].dst){
            gblock = plink[i].src >> (phd->block_shift - phd->page_shift);
            break;
        }
        DPRT("garbage block %u.\n", gblock);
    }

    ret = nvram_erase_block(gblock << phd->block_shift);
    if(ret < 0){
        ret = -EIO;
        PRT("Fail to erase the colloct block %u.\n", phd->rblock[BLOCK_COLLECT] >> phd->block_size);
        goto _end;
    }

    //step 3: copy the file pages according to the link table 
    for(i = 0; i < phd->pb; i++){
        if(plink[i].dst && plink[i].src){
            ret = nvram_phy_read(plink[i].dst << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to read dst page %u.\n", plink[i].dst);
                goto _end;
            }
            rlen = 0;
            ret = nvram_phy_write(plink[i].src << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to write src page %u.\n", plink[i].src);
                goto _end;
            }

            DPRT("copy from dst %u to src %u.\n", plink[i].dst, plink[i].src);
        }
    }

    //step 4: clear the gabage bit map and set free page bit map 
   for(i = 0; i < phd->pb; i++){
        clear_gpt(plink[i].src);
        if(plink[i].dst){
            clear_fpt(plink[i].src);
        }else{
            set_fpt(plink[i].src);
            DPRT("Collect grabage page %u.\n", plink[i].src);
        }
    }

    //step 5: erase collect block
    ret = nvram_erase_block(phd->rblock[BLOCK_COLLECT]);
    if(ret < 0){
        ret = -EIO;
        PRT("Fail to erase the colloct block %u.\n", phd->rblock[BLOCK_COLLECT] >> phd->block_shift);
        goto _end;
    }

_end:
    return ret;
}

static int nvram_prepare_space(u32 size)
{
    int ret = 0;
    u32 i = 0, j = 0, count = 0, free = 0, sum = 0, base = 0;
    struct nvram_collect_header *phead = phd->pchead;
    struct nvram_collect_link *plink = NULL;
    
    plink = phead->ltable;
    sum = 1 + (size >> phd->page_shift);
    free = sum_free_page();
    
    if(sum <= free){
        DPRT("%u free pages is enough to store size %u(%u pages)\n", free, size, sum);
        return 0;
    }else{
        DPRT("%u free pages is not enough to store size %u(%u pages)\n", free, size, sum);
    }
    DPRT("1) Free:%u, Garbage:%u, Requst:%u.\n", sum_free_page(), sum_garbage_page(), sum);
    i = phd->rblock[BLOCK_DATA_BASE] >> phd->page_shift;
    for( ; i < phd->pages; i += phd->pb){
        if(free >= sum){
            ret = 0;
            break;
        }
        count = 0;
        base = phd->rblock[BLOCK_COLLECT] >> phd->page_shift;
        memset(phead->ltable, 0,  sizeof(struct nvram_collect_link) *phd->pb);
        //scan one block
        for(j = 0; j < phd->pb; j++){
            phead->ltable[j].src = i + j;
            if(!get_gpt(i + j)){
                if(!get_fpt(i + j)){//file data page
                    phead->ltable[j].dst = base;
                    base++;
                }else{//it was free page
                    phead->ltable[j].dst = 0;
                }
            }else{
                //garbage page
                count++;
                phead->ltable[j].dst = 0;
            }
        }

        //there are garbage pages in the block
        if(count > 0){
            if(phd->pb == count){//all the block is garbage
                DPRT("Collect garbage block %u.\n", i >> (phd->block_shift - phd->page_shift));
                ret = nvram_erase_block(i << phd->page_shift);
                if(ret < 0){
                    PRT("Fail to erase the garbage block %u.\n", i >> (phd->block_shift - phd->page_shift));
                    continue;
                }
                for(j = 0; j < phd->pb; j++){
                    if(!get_fpt(i + j)){
                        DPRT("Collect block garbage: page %u\n", i + j);
                        free++;
                    }
                    clear_gpt(i + j);
                    set_fpt(i + j);
                }
            }else{
                DPRT("Collect %u garbage pages in block %u.\n", count, i >> (phd->block_shift - phd->page_shift));
                free += nvram_collect_swap(phead);
            }
        }
    }
    DPRT("2) Free:%u, Garbage:%u, Requst:%u.\n", sum_free_page(), sum_garbage_page(), sum);
    if(free < sum){
        ret = -ENOSPC;
        PRT("Fail to collect enough page for %u.\n", size);
    }
    return ret;
}

static int nvram_backup_file(u8 * path)
{
    int ret = 0, sum = 0, bsize = 0;
    int r = 0, fd = -1;
    u32 rlen = 0, offset = 0, page1 = 0, page2 = 0, first = 0;
    u8 *buffer = phd->buffer, *pbuf = NULL;
    mm_segment_t old_fs = get_fs();
    struct stat stat;
    struct nvram_page_header *phg = NULL;
    struct nvram_file_node *pfnew = NULL, *pfold = NULL, *pftmp = NULL;
    struct list_head *plist = &phd->file_restore_list;

    set_fs(KERNEL_DS);
    if(0 != sys_access(path, 0)){
        ret = -EINVAL;
        PRT("access user file %s error.\n", path);
        goto _end;
    }
    if( 0 != sys_newstat(path, &stat)){
        ret = -EINVAL;
        PRT("stat user file %s error.\n", path);
        goto _end;
    }

    ret = nvram_prepare_space(stat.st_size);
    if(ret < 0){
        ret = -ENOSPC;
        PRT("no space to backup user file %s, which size is %lu\n", path, stat.st_size);
        goto _end;
    }
    memset(buffer, 0, phd->page_size);
    pfnew = kzalloc(sizeof(struct nvram_file_node) + sizeof(struct nvram_file) + strlen(path) + 1, GFP_KERNEL);
    if(NULL == pfnew){
        ret = -ENOMEM;
        PRT("fail to alloc pfnew for %s.", path);
        goto _end;
    }

    phd->seqnum ++;
    pfnew->pfile->seqnum = phd->seqnum;
    pfnew->pfile->uid = stat.st_uid;
    pfnew->pfile->gid = stat.st_gid;
    pfnew->pfile->mode = stat.st_mode;
    pfnew->pfile->size = stat.st_size;
    pfnew->pfile->len = strlen(path) + 1;
    memcpy(pfnew->pfile->path, path, strlen(path));

    phg = (struct nvram_page_header *)buffer;
    plist = &phd->file_restore_list;
    list_for_each_entry(pftmp, plist, node) {
        if(!strcmp(pftmp->pfile->path, path)){
            DPRT("find an old file node %s.\n", pftmp->pfile->path);
            pfold = pftmp;
            break;
        }
    }

    //write the new file into pages
    fd = sys_open((const char __user *)path, O_RDONLY, 0);
    if(fd < 0){
        ret = -EINVAL;
        PRT("open user file %s error.\n", path);
        goto _end;
    }
    
    sum = pfnew->pfile->size;
    offset = sizeof(struct nvram_page_header);
    bsize = phd->page_size - sizeof(struct nvram_page_header);
    first = get_free_page();
    if(0 == first){
        ret = -ENOSPC;
        PRT("no free page to save file %s.\n", path);
        goto _end;
    }
    while(sum > 0){
        //the page buffer is enough to write
        if(offset >= phd->page_size){
            offset = sizeof(struct nvram_page_header);
            page1 = get_free_page();
            if(0 == page1){
                ret = -ENOSPC;
                PRT("no free page to save file");
                goto _end;
            }
            clear_fpt(page1);
            page2 = get_free_page();
            if(0 == page2){
                ret = -ENOSPC;
                PRT("no free page to save file");
                goto _end;
            }
            
            phg->magic = PAGE_MAGIC;
            phg->next = page2;
            phg->seqnum = pfnew->pfile->seqnum;
            ret = nvram_phy_write(page1 << phd->page_shift, phd->page_size, &rlen, phd->buffer);
            if(rlen != phd->page_size){
                clear_fpt(page1);
                set_gpt(page1);
                ret = -EIO;
                PRT("Fail to write  page %u.\n", page1);
                goto _end;
            }
            DPRT("save file data into %u page, offset = %u.\n", page1, offset);
        }

        pbuf = buffer + offset;
        r = sys_read(fd, pbuf, (phd->page_size - offset) );
        if(r <= 0){
            ret = -EINVAL;
            PRT("read user file %s error.\n", path);
            goto _end;
        }
        DPRT("read %d bytes from %s.\n", r, path);
        offset += r;
        sum -= r;
    }

    //write the last file data page
    if(offset > sizeof(struct nvram_page_header)){
        page1 = get_free_page();
        if(0 == page1){
                ret = -ENOSPC;
                PRT("no free page to save file");
                goto _end;
            }
        clear_fpt(page1);
        phg->magic = PAGE_MAGIC;
        phg->next = 0;
        phg->seqnum = pfnew->pfile->seqnum;
        ret = nvram_phy_write(page1 << phd->page_shift, phd->page_size, &rlen, phd->buffer);
        if(rlen != phd->page_size){
            clear_fpt(page1);
            set_gpt(page1);
            ret = -EIO;
            PRT("Fail to write  page %u.\n", page1);
            goto _end;
        }
        DPRT("save last file data into %u page, offset =%u.\n", page1, offset);
    }
    pfnew->pfile->page = first;
    list_add_tail(&pfnew->node, plist);
    first = 0;

    //delete the old file node if exist
    if(pfold){
        DPRT("Delet the old file %s.\n", pfold->pfile->path);
        list_del(&pfold->node);
        page1= pfold->pfile->page;
        while(page1){
            ret = nvram_phy_read(page1 << phd->page_shift, sizeof(struct nvram_page_header), &rlen, (u8 *)phg);
            if(rlen != sizeof(struct nvram_page_header)){
                PRT("Fail to read the old file page %u header.\n", offset);
                break;
            }
            if(PAGE_MAGIC != phg->magic){
                PRT("Invalid page magic 0x%x for old file page %u.\n", phg->magic, offset);
                break;
            }

            if(phg->seqnum != pfold->pfile->seqnum){
                 PRT("invalid seqnum phg.seqnum=%u, file.seqnum=%u.\n", phg->seqnum, pfold->pfile->seqnum);
                 break;
            }
            set_gpt(page1);
            DPRT("set page %u garbage.\n", page1);
            page1 = phg->next;
        }
        kfree(pfold);
        pfold = NULL;
    }

    //refresh the nvram header
    nvram_header_save();

_end:
    if(fd > 0){
        sys_close(fd);
    }
    set_fs(old_fs);
    if(ret < 0){
        if(pfnew){
            kfree(pfnew);
            pfnew = NULL;
        }
    }
    return ret;
}

static int nvram_delete_file(u8 * path)
{
    int ret = 0;
    u32 rlen = 0, offset = 0, page;
    struct nvram_page_header phg;
    struct nvram_file_node *pfold = NULL, *pftmp = NULL;
    struct list_head *plist = &phd->file_restore_list;

    list_for_each_entry(pftmp, plist, node) {
        if(!strcmp(pftmp->pfile->path, path)){
            DPRT("Find %s for delete.\n", path);
            pfold = pftmp;
            break;
        }
    }

    if(NULL == pfold){
        DPRT("%s is not exist.\n", path);
        ret = -EINVAL;
        goto _end;
    }else{
        //delete the old file node if exist
        DPRT("delete file %s.\n", pfold->pfile->path);
        list_del(&pfold->node);
        page= pfold->pfile->page;
        while(page){
            ret = nvram_phy_read(page << phd->page_shift, sizeof(struct nvram_page_header), &rlen, (u8 *)&phg);
            if(rlen != sizeof(struct nvram_page_header)){
                PRT("Fail to read the old file page %u header.\n", offset);
                break;
            }
            if(PAGE_MAGIC != phg.magic){
                PRT("Invalid page magic 0x%x for old file page %u.\n", phg.magic, offset);
                break;
            }
            
            if(phg.seqnum != pfold->pfile->seqnum){
                 PRT("invalid seqnum phg.seqnum=%u, file.seqnum=%u", phg.seqnum, pfold->pfile->seqnum);
                 break;
            }
            
            set_gpt(page);
            DPRT("set page %u garbage.\n", page);
            page = phg.next;
        }
        kfree(pfold);
        pfold = NULL;
    }

    //refresh the nvram header
    nvram_header_save();
_end:
    return ret;
}

static int nvram_restore_node(struct nvram_file_node *pfnode)
{
    int ret = 0, sum = 0;
    int w = 0, fd = -1;
    u32 rlen = 0, offset = 0, page = 0;
    u8 *buffer = phd->buffer, *pbuf = NULL, *path = NULL;
    mm_segment_t old_fs = get_fs();
    struct nvram_page_header *phg = NULL;
    struct nvram_file *pfile = NULL;
    
    if(NULL == pfnode){
        return -EINVAL;
    }

    set_fs(KERNEL_DS);
    pfile = pfnode->pfile;
    path = pfile->path;
    //create the new file
    fd = sys_open((const char __user *)path, O_RDWR | O_CREAT | O_TRUNC, 0660);
    if(fd < 0){
        ret = -EIO;
        PRT("open user file %s error.\n", path);
        goto _end;
    }
    
    sum = pfile->size;
    phg = (struct nvram_page_header *)buffer;
    page = pfile->page;
    if(sum <= 0){
        ret = -EINVAL;
        PRT("invalid file size %d to file %s node.\n", sum, path);
        goto _end;
    }
    DPRT("%s size is %d.\n", path, sum);
    offset = phd->page_size;// trig the first page read
    while(sum > 0){
        //read file data page at begining
        if(offset >= phd->page_size){
            DPRT("read file data from %u page, offset = %u.\n", page, offset);
            ret = nvram_phy_read(page << phd->page_shift, phd->page_size, &rlen, buffer);
            if(rlen != phd->page_size){
                ret = -EIO;
                PRT("Fail to read file %s data page %u.\n", path, page);
                goto _end;
            }
            if(PAGE_MAGIC != phg->magic){
                PRT("Invalid %s data page magic 0x%x data page %u.\n", path, phg->magic, page);
                ret = -EINVAL;
                goto _end;
            }
            if(phg->seqnum != pfile->seqnum){
                PRT("Invalid %s data page seqnum %u data page %u.\n", path, phg->seqnum, page);
                ret = -EINVAL;
                goto _end;
            }
            page = phg->next; 
            offset = sizeof(struct nvram_page_header);
        }

        pbuf = buffer + offset;
        w = phd->page_size - offset;
        if(sum < w){
            w = sum;
        }
        w = sys_write(fd, pbuf, w);
        if(w <= 0){
            ret = -EIO;
            PRT("write user file %s error.\n", path);
            goto _end;
        }
        DPRT("write %d bytes into %s.\n", w, path);
        offset += w;
        sum -= w;
    }

    ret = sys_fchown(fd, pfile->uid, pfile->gid);
    if(ret < 0){
        PRT("Fail to chown file %s.\n", path);
        ret = -EIO;
        goto _end;
    }
    
    ret = sys_fchmod(fd, pfile->mode);
    if(ret < 0){
        PRT("Fail to chmod file %s.\n", path);
        ret = -EIO;
        goto _end;
    }

    DPRT("Restore file %s ok.\n", path);
_end:
    if(fd > 0){
        sys_close(fd);
        fd = -1;
    }
    if(ret < 0){
        sys_unlink(path);
    }
    set_fs(old_fs);
    return ret;
}

static int nvram_restore_file(u8 *path)
{
    int ret = -EINVAL;
    struct nvram_file_node *pfnode = NULL;
    struct list_head *plist = &phd->file_restore_list;

    list_for_each_entry(pfnode, plist, node) {
        if(!strncmp(pfnode->pfile->path, path, strlen(path))){
            ret = nvram_restore_node(pfnode);
            if(ret < 0){
                PRT("Fail to restore file %s.\n", pfnode->pfile->path);
            }
            break;
        }
    }

    return ret;
}

static int nvram_restore_all(void)
{
    int ret = 0;
    struct nvram_file_node *pfnode = NULL;
    struct list_head *plist = &phd->file_restore_list;

    list_for_each_entry(pfnode, plist, node) {
        ret = nvram_restore_node(pfnode);
        if(ret < 0){
            PRT("Fail to restore file %s.\n", pfnode->pfile->path);
            break;
        }
    }

    return ret;
}

static int misc_nvram_open(struct inode *inode, struct file *filp)
{
    DPRT("%d open nvram.\n", current->pid);
    return 0;
}

#define NVRAM_IOCTL_BACKUP           _IOW('N', 0x01, u8 *)
#define NVRAM_IOCTL_RESTORE         _IOW('N', 0x02, u8 *)
#define NVRAM_IOCTL_RESTORE_ALL _IO('N', 0x03)
#define NVRAM_IOCTL_DELETE	           _IOW('N', 0x04, u8 *)

static u8 * misc_get_path(u8 __user *argp)
{
    int len = 0;
    u8 *path =NULL;

    len = strlen_user(argp);
    if((len <= 0) || (len >= phd->page_size - sizeof(struct nvram_file) - sizeof(struct nvram_header))){
        PRT("invalid user path.\n");
        goto _end;
    }
    path = kzalloc(len + 1, GFP_KERNEL);
    if(NULL == path){
        PRT("fail to alloc user path.\n");
        goto _end;
    }
    if(strncpy_from_user(path, argp, len) < 0){
        kfree(path);
        path = NULL;
    }
_end:
    return path;
}
static u8 *nvram_user_path;
static int nvram_user_ret;
static DECLARE_COMPLETION(nvram_user_ioctl);
static void nvram_user_backup(struct work_struct *unused)
{
    if(nvram_user_path){
        nvram_user_ret = nvram_backup_file(nvram_user_path);
    }
    complete(&nvram_user_ioctl);
}
static void nvram_user_restore(struct work_struct *unused)
{
    if(nvram_user_path){
        nvram_user_ret = nvram_restore_file(nvram_user_path);
    }
    complete(&nvram_user_ioctl);
}
static void nvram_user_restore_all(struct work_struct *unused)
{
    nvram_user_ret = nvram_restore_all();
    complete(&nvram_user_ioctl);
}
static void nvram_user_delete(struct work_struct *unused)
{
    if(nvram_user_path){
        nvram_user_ret = nvram_delete_file(nvram_user_path);
    }
    complete(&nvram_user_ioctl);
}
static DECLARE_WORK(user_backup_work, nvram_user_backup);
static DECLARE_WORK(user_restore_work, nvram_user_restore);
static DECLARE_WORK(user_restore_all_work, nvram_user_restore_all);
static DECLARE_WORK(user_delete_work, nvram_user_delete);
static long misc_nvram_ioctl(struct file *file, unsigned int
		cmd, unsigned long arg)
{
    u8 __user *argp = (void __user *) arg;

    mutex_lock(&phd->mlock);

    nvram_user_ret = 0;
    
    switch (cmd) {
        case NVRAM_IOCTL_BACKUP:
            nvram_user_path = misc_get_path(argp);
            if(NULL == nvram_user_path){
                DPRT("Invalid input path.\n");
                nvram_user_ret = -EINVAL;
                break;
            }
            DPRT("User request backup %s.\n", nvram_user_path);
            queue_work(nvram_work_queue, &user_backup_work);
            wait_for_completion(&nvram_user_ioctl);
            break;
        case NVRAM_IOCTL_RESTORE:
            nvram_user_path = misc_get_path(argp);
            if(NULL == nvram_user_path){
                DPRT("Invalid input path.\n");
                nvram_user_ret = -EINVAL;
                break;
            }
            DPRT("User request restore %s.\n", nvram_user_path);
            queue_work(nvram_work_queue, &user_restore_work);
            wait_for_completion(&nvram_user_ioctl);
            break;
        case NVRAM_IOCTL_RESTORE_ALL:
            DPRT("User request restore all.\n");
            queue_work(nvram_work_queue, &user_restore_all_work);
            wait_for_completion(&nvram_user_ioctl);
            break;
        case NVRAM_IOCTL_DELETE:
            nvram_user_path = misc_get_path(argp);
            if(NULL == nvram_user_path){
                DPRT("Invalid input path.\n");
                nvram_user_ret = -EINVAL;
                break;
            }
            DPRT("User request delete %s.\n", nvram_user_path);
            queue_work(nvram_work_queue, &user_delete_work);
            wait_for_completion(&nvram_user_ioctl);
            break;
        default:
            nvram_user_ret = -ENOIOCTLCMD;
            break;
    }
    if(nvram_user_path){
        kfree(nvram_user_path);
        nvram_user_path = NULL;
    }
    mutex_unlock(&phd->mlock);
    DPRT("User request result ret = %d.\n", nvram_user_ret);
    return nvram_user_ret;
}

static int misc_nvram_release(struct inode *inode, struct file *filp)
{
    DPRT("%d close nvram.\n", current->pid);
    return 0;
}
static const struct file_operations misc_nvram_fops = {
	.owner = THIS_MODULE,
	.open = misc_nvram_open,
	.unlocked_ioctl = misc_nvram_ioctl,
	.release = misc_nvram_release,
};

static struct miscdevice misc_nvram_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "nvram",
	.fops = &misc_nvram_fops,
};
static void nvram_handle_exit(void)
{
    if(NULL == phd->mtd){
        return ;
    }

    mutex_lock(&phd->mlock);
    nvram_header_destroy();
    if(phd->bbt){
        kfree(phd->bbt);
        phd->bbt = NULL;
    }

    if(phd->fpt){
        kfree(phd->fpt);
        phd->fpt = NULL;
    }

    if(phd->gpt){
        kfree(phd->gpt);
        phd->gpt = NULL;
    }

    if(phd->buffer){
        kfree(phd->buffer);
        phd->buffer = NULL;
    }

    if(phd->pchead){
        kfree(phd->pchead);
        phd->pchead = NULL;
    }

    misc_deregister(&misc_nvram_device);

    mutex_unlock(&phd->mlock);
}

static int nvram_proc_infor_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int len = 0, i = 0;
    u32 v = 0, last = 0, rlen = 0, sum = 0;
    struct nvram_file_node *pfnode;
    struct nvram_file *pfile;
    struct nvram_page_header ph;

    p += sprintf(p, "\n VIA NVRAM %s INFORMATION \n", nvram_version);
    p += sprintf(p, "    HEADER_MAGIC:0x%x, COLLECT_MAGIC:0x%x, PAGE_MAGIC:0x%x.\n", HEADER_MAGIC, COLLECT_MAGIC, PAGE_MAGIC);
    p += sprintf(p, "    tSize: 0x%x, bSize:0x%x, pSize:0x%x.\n", phd->partition_size, phd->block_size, phd->page_size);
    p += sprintf(p, "    blocks:%u, pages:%u, pb:%u  index:%u, seqnum:%u\n", phd->blocks, phd->pages, phd->pb, phd->index, phd->seqnum);
    p += sprintf(p, "    header0:0x%x(%u block), header1:0x%x(%u block), collect:0x%x(%u block), data:0x%x(%u block).\n", \
                phd->rblock[BLOCK_HEADER_0],  phd->rblock[BLOCK_HEADER_0] >> phd->block_shift, \
               phd->rblock[BLOCK_HEADER_1],  phd->rblock[BLOCK_HEADER_1] >> phd->block_shift, \
               phd->rblock[BLOCK_COLLECT],  phd->rblock[BLOCK_COLLECT] >> phd->block_shift, \
               phd->rblock[BLOCK_DATA_BASE],  phd->rblock[BLOCK_DATA_BASE] >> phd->block_shift );
    
    p += sprintf(p, "\n    %u Restore Files:\n", phd->header.count);
    sum = 1;
    list_for_each_entry(pfnode, &phd->file_restore_list, node) {
        pfile = pfnode->pfile;
        p += sprintf(p, "    %u) File Path: %s\n", sum++, pfile->path);
        p += sprintf(p, "        seqnum:%u, size: %u, page: %u, uid:%u, gid:%u, mode:%o\n", pfile->seqnum, pfile->size, pfile->page, pfile->uid, pfile->gid, pfile->mode);
        v = pfile->page;
        i = 0;
#if 0 //print all the pages, mayby overrun the proc buffer
        p += sprintf(p, "        page link: \n");
        p += sprintf(p, "            %04u) ", i);
        while(v){
            p += sprintf(p, "%u-", v);
            i++;
            if(0 == (i % 16)){
                p += sprintf(p, "\n            %04u) ", i);
            }
            nvram_phy_read(v << phd->page_shift, sizeof(ph), &rlen, (u8 *)&ph);
            v = ph.next;
            if(ph.magic != PAGE_MAGIC){
                p += sprintf(p, "%s(0x%x)", "BadMagic", ph.magic);
                break;
            }
            if(ph.seqnum != pfile->seqnum){
                 p += sprintf(p, "%s(%u)", "BadSeq", ph.seqnum);
                 break;
            }
            

        }
        p += sprintf(p, "EOF\n");
#else
        last = v;
        i++;
        p += sprintf(p, "        First:%u, ", pfile->page); 
        while(v){
            nvram_phy_read(v << phd->page_shift, sizeof(ph), &rlen, (u8 *)&ph);
            last = v;
            v = ph.next;
            if(v){
                i++;
            }
            if(ph.magic != PAGE_MAGIC){
                p += sprintf(p, "%s(%u magic=0x%x) ", "BadMagic", v, ph.magic);
                break;
            }
            if(ph.seqnum != pfile->seqnum){
                 p += sprintf(p, "%s(%u seqnum=0x%x) ","BadSeq", v, ph.seqnum);
                 break;
            }
        }
        p += sprintf(p, "Last:%u, Total:%d. \n", last, i);
    }
#endif

    len = p - page;
    if (len > off) {
        len -= off;
    }else {
        len = 0;
    }

    return len < count ? len : count;
}

static int nvram_proc_bbt_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int len = 0;
    u32 i, tsize, sum;
    
    p += sprintf(p, "\n--- Bad block Bit Map ---\n");
    sum = 0;
    tsize = (phd->blocks+ 32)/32;
    for(i = 0; i < tsize; i++){
        if(0 == (i % 8)){
            p += sprintf(p, "    %08u) ", i * 32 * 8);
        }
        p += sprintf(p, "%08x ", phd->bbt[i]);
        if(0 == ((i + 1) % 8)){
            p += sprintf(p, "\n");    
        }
    }

    p += sprintf(p, "\nTotal: %u,\n", sum_bad_block());

    len = p - page;
    if (len > off) {
        len -= off;
    }else {
        len = 0;
    }

    return len < count ? len : count;
}

static int nvram_proc_fpt_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int len = 0;
    u32 i, tsize, sum;
    
    p += sprintf(p, "\n--- Free Page Bit Map ---\n");
    sum = 0;
    tsize = (phd->pages + 32)/32;
    for(i = 0; i < tsize; i++){
        if(0 == (i % 8)){
            p += sprintf(p, "    %08u) ", i * 32);
        }
        p += sprintf(p, "%08x ", phd->fpt[i]);
        if(0 == ((i + 1) % 8)){
            p += sprintf(p, "\n");    
        }
    }
   
    p += sprintf(p, "\nTotal: %u,\n", sum_free_page());

    len = p - page;
    if (len > off) {
        len -= off;
    }else {
        len = 0;
    }

    return len < count ? len : count;
}

static int nvram_proc_gpt_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int len = 0;
    u32 i, tsize, sum;
    
    p += sprintf(p, "\n--- Garbage Page Bit Map ---\n");
    sum = 0;
    tsize = (phd->pages + 32)/32;
    for(i = 0; i < tsize; i++){
        if(0 == (i % 8)){
            p += sprintf(p, "    %08u) ", i * 32);
        }
        p += sprintf(p, "%08x ", phd->gpt[i]);
        if(0 == ((i + 1) % 8)){
            p += sprintf(p, "\n");    
        }
    }

    p += sprintf(p, "\nTotal: %u,\n", sum_garbage_page());

    len = p - page;
    if (len > off) {
        len -= off;
    }else {
        len = 0;
    }

    return len < count ? len : count;
}

static int nvram_proc_debug_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    char *p = page;
    int len = 0;
    
    p += sprintf(p, "%lu\n", nvram_debug);

    len = p - page;
    if (len > off) {
        len -= off;
    }else {
        len = 0;
    }

    return len < count ? len : count;
}
static int nvram_proc_debug_write(struct file *file, const char __user *buffer,
				unsigned long count, void *data)
{
	char buf[] = "0x00000000";
	unsigned long len = min(sizeof(buf) - 1, (u32)count);
	char *p = (char *)buf;
	unsigned long val;

	if (copy_from_user(buf, buffer, len))
		return count;
	buf[len] = 0;
	if (p[1] == 'x' || p[1] == 'X' || p[0] == 'x' || p[0] == 'X') {
		p++;
		if (p[0] == 'x' || p[0] == 'X')
			p++;
		val = simple_strtoul(p, &p, 16);
	} else
		val = simple_strtoul(p, &p, 10);
	if (p == buf)
		PRT(": %s is not in hex or decimal form.\n", buf);
	else
		nvram_debug = val;

	return strnlen(buf, count);
}

static u32 page_dump;
static int nvram_proc_dump_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    u32 rlen;
    char *p = page;
    int len = 0, i = 0, pnum = 0, offset= 0, max = 512;
    pnum = page_dump >> 16;
    offset = page_dump & (0xFFFF);
    p += sprintf(p, "page_dump: 0x%08x.\n", page_dump);
    if(pnum >= phd->pages){
        p += sprintf(p, "invalid page number %d.\n", pnum);
        goto _end;
    }else{
        p += sprintf(p, "dump %d page, offset %d:\n", pnum, offset);
    }
    mutex_lock(&phd->mlock);
    nvram_phy_read(pnum << phd->page_shift, phd->page_size, &rlen, phd->buffer);
    if(rlen != phd->page_size){
        PRT("Fail to read page %u.\n", pnum);
    }else{
        for(i = 0; (i + offset < phd->page_size) && (i < max); i++){
            if(0 == (i % 16)){
                p += sprintf(p, "    %08u) ", offset + i);
            }
            p += sprintf(p, "%02x ", phd->buffer[i + offset]);
            if(0 == ((i + 1) % 16)){
                p += sprintf(p, "\n");    
            }
        }
    }
    mutex_unlock(&phd->mlock);
_end:
    len = p - page;
    if (len > off) {
        len -= off;
    }else {
        len = 0;
    }

    return len < count ? len : count;
}
static int nvram_proc_dump_write(struct file *file, const char __user *buffer,
				unsigned long count, void *data)
{
    char buf[32] = {0};
    char *p = (char *)buf;
    unsigned long val;
    int len = 0;

    len = (count < (sizeof(buf) - 1)) ? count : (sizeof(buf) - 1);

    if (copy_from_user(buf, buffer, len))
    	return count;
    
    val = simple_strtoul(buf, &p, 16);

    if (p == buf)
    	PRT(": %s is not in hex or decimal form.\n", buf);
    else
    	page_dump = val;

    return count;
}
static void nvram_handle_init(struct work_struct *work)
{
    int ret = 0;
    struct proc_dir_entry *entry = NULL;
    struct proc_dir_entry *dir = NULL;

    /*init the handle*/
    mutex_init(&phd->mlock);
    INIT_LIST_HEAD(&phd->file_restore_list);

    phd->index = 0;
    phd->partition_size = phd->mtd->size;
    phd->block_size = phd->mtd->erasesize;
    phd->block_shift = phd->mtd->erasesize_shift;
    phd->block_mask = phd->mtd->erasesize_mask;
    phd->page_size = phd->mtd->writesize;
    phd->page_shift = phd->mtd->writesize_shift;
    phd->page_mask = phd->mtd->writesize_mask;
    phd->blocks =  (phd->partition_size) >> (phd->block_shift);
    phd->pages = (phd->partition_size) >> (phd->page_shift);
    phd->pb = phd->block_size / phd->page_size;

    DPRT("psize:0x%x, bsize:0x%x, bshift:%u, bmask:0x%x, psize:%u, pshift:%u, pmask:0x%x, blocks:%u, pages:%u, pb:%u.\n", \
               phd->partition_size, phd->block_size, phd->block_shift, phd->block_mask, \
               phd->page_size, phd->page_shift, phd->page_mask, phd->blocks, phd->pages, phd->pb);
    phd->buffer = kzalloc(phd->page_size, GFP_KERNEL);
    if(NULL == phd->buffer){
        ret = -ENOMEM;
        PRT("Fail to alloc buffer.\n");
        goto _end;
    }
    phd->pchead = kzalloc(sizeof(struct nvram_collect_header) + (sizeof(struct nvram_collect_link) * phd->pb), GFP_KERNEL);
    if(NULL == phd->pchead){
        ret = -ENOMEM;
        PRT("Fail to alloc collect header.\n");
        goto _end;
    }
    ret = nvram_bitmaps_create();
    if(ret < 0){
        PRT("Fail to creat bitmap tables.\n");
        goto _end;
    }
    ret = nvram_collect_check();
    if(ret < 0){
        PRT("Fail to gabage collection check.\n");
        goto _end;
    }
    //register the misc device
    ret = misc_register(&misc_nvram_device);
    if(ret < 0){
        PRT("misc regiser via nvram failed\n");
        goto _end;
    }

    dir = proc_mkdir("nvram", NULL);
    if (!dir){
        PRT(" mkdir /proc/nvram failed\n");
    }
    else{
        entry = create_proc_entry("infor", S_IRUGO, dir);
        if (entry){
            entry->read_proc = nvram_proc_infor_read;
            entry->write_proc = NULL;
        }

        entry = create_proc_entry("debug", S_IRUGO | S_IWUSR | S_IWGRP, dir);
        if (entry){
            entry->read_proc = nvram_proc_debug_read;
            entry->write_proc = nvram_proc_debug_write;
        }

        entry = create_proc_entry("fpt", S_IRUGO, dir);
        if (entry){
            entry->read_proc = nvram_proc_fpt_read;
            entry->write_proc = NULL;
        }

        entry = create_proc_entry("gpt", S_IRUGO, dir);
        if (entry){
            entry->read_proc = nvram_proc_gpt_read;
            entry->write_proc = NULL;
        }

        entry = create_proc_entry("bbt", S_IRUGO, dir);
        if (entry){
            entry->read_proc = nvram_proc_bbt_read;
            entry->write_proc = NULL;
        }

        entry = create_proc_entry("dump", S_IRUGO, dir);
        if (entry){
            entry->read_proc = nvram_proc_dump_read;
            entry->write_proc = nvram_proc_dump_write;
        }
    }
    DPRT(" init success \n");
_end:
    if(ret < 0){
        nvram_handle_exit();
    }
    return ;
}
static DECLARE_WORK(init_work, nvram_handle_init);

static void nvram_mtd_notify_add(struct mtd_info *mtd)
{

    if (strcmp(mtd->name, NVRAM_PARTITION_LABEL))
        return;
    DPRT("Detect %s partition.\n", NVRAM_PARTITION_LABEL);
    memset(phd, 0, sizeof(struct nvram_handle));
    phd->mtd = mtd;
    
    queue_work(nvram_work_queue, &init_work);
}

static void nvram_mtd_notify_remove(struct mtd_info *mtd)
{
    if (mtd == phd->mtd) {
        phd->mtd = NULL;
        nvram_handle_exit();
        PRT("Unbound from %s\n", mtd->name);
    }
}

static struct mtd_notifier nvram_mtd_notifier = {
	.add	= nvram_mtd_notify_add,
	.remove	= nvram_mtd_notify_remove,
};

int __init  nvram_init(void)
{
    int ret = 0;
    
    nvram_work_queue = create_singlethread_workqueue("nvram");
    if (nvram_work_queue == NULL) {
        ret = -ENOMEM;
    }
    register_mtd_user(&nvram_mtd_notifier);
    return ret;
}

module_init(nvram_init);

