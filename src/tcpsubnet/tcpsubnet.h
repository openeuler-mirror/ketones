// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TCPSUBNET_H
#define __TCPSUBNET_H

#define MAX_NETS	16
#define MAX_LENS	80

struct subnet {
	const char *netinfo;
	unsigned int netaddr;
	unsigned int netmask;
};

#endif
