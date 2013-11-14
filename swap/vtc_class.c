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
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/sysdev.h>
#include <linux/timer.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <vtc/vtc_class.h>


static struct class *vtc_class;
LIST_HEAD(vtc_head);
INIT_MUTEX(vtc_mlock);

static ssize_t vtc_debug_show(struct device *dev, 
		struct device_attribute *attr, char *buf)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);

	/* no lock needed for this */
	led_update_brightness(led_cdev);

	return sprintf(buf, "%u\n", led_cdev->brightness);
}

static ssize_t vtc_debug_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	ssize_t ret = -EINVAL;
	char *after;
	unsigned long state = simple_strtoul(buf, &after, 10);
	size_t count = after - buf;

	if (isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		if (state == LED_OFF)
			led_trigger_remove(led_cdev);
		led_set_brightness(led_cdev, state);
	}

	return ret;
}
static struct device_attribute vtc_class_attrs[] = {
	__ATTR(debug, 0664, vtc_debug_show, vtc_debug_store),
	__ATTR_NULL,
};

static platform_device pvtc = {
	.name = "pvtc",
};

struct vtc_class_dev * vtc_classdev_register(const char *name)
{
	int ret = 0;
	struct vtc_class_dev *vdev = NULL;

	mutex_lock(&vtc_mlock);
	list_for_each_entry(vdev, &vtc_head, node) {
    	if (!strcmp(vdev->name, name)){
			printk("vtc class dev %s already exist.\n", name);
			goto _end;
		}            
	}

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev){
		ret = -ENOMEM;
		goto _err;
	}

	vdev->name = name;
	vdev->debug = VTC_DEBUG_DEFAULT;
	vdev->dev = device_create(vtc_class, &pvtc.dev, 0, vdev, "%s", name);
_end:
	mutex_unlock(&vtc_mlock);
	return vdev;
_err:
    mutex_unlock(&vtc_mlock);
	if (vdev){
		kfree(dev);
	}
    return NULL;
}

int vtc_classdev_unregister(const char *name)
{
}

static int __init vtc_init(void)
{
	int ret = 0;
	vtc_class = class_create(THIS_MODULE, "vtc");
	if (IS_ERR(vtc_class))
		return PTR_ERR(vtc_class);
	vtc_class->dev_attrs = vtc_class_attrs;
	ret = platform_device_register(&pvtc);
	if (ret < 0){
		printk("Fail to register platform deivec %s.\n", pvtc->name);
		class_destroy(vtc_class);
	}
	return ret;
}

static void __exit leds_exit(void)
{
	class_destroy(vtc_class);
	platform_device_unregister(&pvtc);
}

subsys_initcall(vtc_init);
module_exit(vtc_exit);
