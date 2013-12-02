/*
 * VTC Class Core
 *
 * Copyright (C) 2013 VIATelecom
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <vtc/vclass.h>

static struct class *vtc_class;
LIST_HEAD(vtc_head);
static DEFINE_MUTEX(vtc_mlock);

static char *debug_type_string[VTC_DEBUG_TYPE_COUNT] = {
	"error",
	"warning",
	"infor",
	"data",
	"debug"
};

static ssize_t vtc_debug_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	int i = 0;
	char *buff = buf;
	struct vtc_class_dev *vdev = dev_get_drvdata(dev);

	for(i = 0; i < VTC_DEBUG_TYPE_COUNT; i++){
		if (vdev->debug & (1 << i)){
			buff += sprintf(buff, " %d:[%s] ",i ,debug_type_string[i]);
		}else{
			buff += sprintf(buff, " %d:%s ",i ,debug_type_string[i]);
		}
	}

	if (buff != buf)
		*(buff-1) = '\n';

	return buff - buf;
}

static ssize_t vtc_debug_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct vtc_class_dev *vdev = dev_get_drvdata(dev);
	ssize_t ret = -EINVAL;
	char *after;
	unsigned long types = simple_strtoul(buf, &after, 16);
	size_t count = after - buf;

	if (isspace(*after))
		count++;

	if (count == size) {
		ret = count;
		types &= ((1 << VTC_DEBUG_TYPE_COUNT) - 1);
		vdev->debug = types;
	}

	return ret;
}

static struct device_attribute vtc_class_attrs[] = {
	__ATTR(debug, 0664, vtc_debug_show, vtc_debug_store),
	__ATTR_NULL,
};

static struct platform_device pvtc = {
	.name = "pvtc",
};

struct vtc_class_dev * vtc_classdev_find(const char * name)
{
	struct vtc_class_dev *vdev = NULL, *tmp = NULL;

	mutex_lock(&vtc_mlock);
	list_for_each_entry(tmp, &vtc_head, node) {
    	if (!strcmp(tmp->name, name)){
			vdev = tmp;
			break;
		}            
	}
	mutex_unlock(&vtc_mlock);
	return vdev;
}
EXPORT_SYMBOL(vtc_classdev_find);

struct vtc_class_dev * vtc_classdev_register(const char *name, int types)
{
	struct vtc_class_dev *vdev = NULL;

	mutex_lock(&vtc_mlock);
	list_for_each_entry(vdev, &vtc_head, node) {
    	if (!strcmp(vdev->name, name)){
			printk("vtc class dev %s already exist.\n", name);
			goto _err;
		}            
	}

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev){
		goto _err;
	}

	vdev->name = name;
	types &= ((1 << VTC_DEBUG_TYPE_COUNT) - 1);
	vdev->debug = types;
	vdev->dev = device_create(vtc_class, &pvtc.dev, 0, vdev, "%s", name);
	if (!vdev->dev){
		printk("fail to create device %s.\n", name);
		goto _err;
	}
	list_add_tail(&vdev->node, &vtc_head);
	
	mutex_unlock(&vtc_mlock);
	return vdev;
_err:
    mutex_unlock(&vtc_mlock);
	if (vdev){
		kfree(vdev);
	}
    return NULL;
}
EXPORT_SYMBOL(vtc_classdev_register);

void vtc_classdev_unregister(const char *name)
{
	struct vtc_class_dev *vdev, *tmp;

	vdev = tmp = NULL;
	mutex_lock(&vtc_mlock);
	list_for_each_entry(tmp, &vtc_head, node) {
    	if (!strcmp(tmp->name, name)){
			vdev = tmp;
			break;
		}            
	}

	if(!vdev){
		goto _end;
	}

	device_destroy(vtc_class, vdev->dev->devt);
	list_del(&vdev->node);
_end:
	mutex_unlock(&vtc_mlock);
	return ;
}
EXPORT_SYMBOL(vtc_classdev_unregister);

static int __init vtc_init(void)
{
	int ret = 0;
	vtc_class = class_create(THIS_MODULE, "vtc");
	if (IS_ERR(vtc_class))
		return PTR_ERR(vtc_class);
	vtc_class->dev_attrs = vtc_class_attrs;
	ret = platform_device_register(&pvtc);
	if (ret < 0){
		printk("Fail to register platform deivec %s.\n", pvtc.name);
		class_destroy(vtc_class);
	}
	VTC_DEBUG_EXPORT("vclass", VTC_ERR | VTC_INF);
	return ret;
}

static void __exit vtc_exit(void)
{
	platform_device_unregister(&pvtc);
	class_destroy(vtc_class);
}

subsys_initcall(vtc_init);
module_exit(vtc_exit);
