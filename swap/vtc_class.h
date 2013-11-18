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
#ifndef __LINUX_VTC_CLASS_H_INCLUDED
#define __LINUX_VTC_CLASS_H_INCLUDED

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

#endif
