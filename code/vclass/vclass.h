/*
 * Driver model for vtc class
 *
 * Copyright (C) 2013 VIA Telecom
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef __LINUX_VCLASS_H_INCLUDED
#define __LINUX_VCLASS_H_INCLUDED

enum debug_type{
	VTC_ERR = 0,
	VTC_WAR = 1,
	VTC_INF = 2,
	VTC_DAT = 3,
	VTC_DBG = 4,
	VTC_DEBUG_TYPE_COUNT
};


#define VTC_DEBUG_DEFAULT  (VTC_ERR | VTC_WAR)

struct vtc_class_dev {
	const char *name;
	u32 debug;
	struct list_head node;
	struct device *dev;
};

extern struct vtc_class_dev * vtc_classdev_find(const char * name);
extern struct vtc_class_dev * vtc_classdev_register(const char *name, int types);
extern void vtc_classdev_unregister(const char *name);

static struct vtc_class_dev *_vtc_class_debug = NULL;
#define VTC_DEBUG_EXPORT(name, types) { \
	if(!_vtc_class_debug) { \
		_vtc_class_debug = vtc_classdev_find(name); \
		if(!_vtc_class_debug) \
			_vtc_class_debug = vtc_classdev_register(name, types); \
		if(!_vtc_class_debug) \
			printk("Fail to export vtc class debug for %s\n", name); \
	} \
} 

#define VDBG(type, fmt, arg...) { \
	if( _vtc_class_debug && (_vtc_class_debug->debug & (1 << type) ) ) \
        	printk("[%s:%s:%d] " fmt,  _vtc_class_debug->name, __FUNCTION__, __LINE__, ##arg); \
}

#define VDBGC(type, fmt, arg...) { \
	if( _vtc_class_debug && (_vtc_class_debug->debug & (1 << type) ) ) \
        	printk(fmt, ##arg); \
}
#endif
