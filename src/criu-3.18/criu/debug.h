#ifndef __DEBUG_H__
#define __DEBUG_H__

#define __ENABLE_DEBUG__

#include <stdio.h>
#include "include/criu-log.h"

#ifdef __ENABLE_DEBUG__
#define dbg_info(fmt, args...)												\
	dprintf(log_get_fd(), "\033[1m\033[32m%s(%d)\033[0m: " fmt,				\
					__FILE__, __LINE__, ##args)

#define err_info(fmt, args...)												\
	dprintf(log_get_fd(), "\033[1m\033[31mErr at %s(%d)\033[0m: " fmt,		\
					__FILE__, __LINE__, ##args)

#define warn_info(fmt, args...)												\
	fprintf(log_get_fd(), "\033[1m\033[33mWarn at %s(%d)\033[0m: " fmt,		\
					__FILE__, __LINE__, ##args)
#else
#define dbg_info(fmt, args...)
#define err_info(fmt, args...)		dprintf(log_get_fd(), fmt, ##args)
#define warn_info(fmt, args...)		dprintf(log_get_fd(), fmt, ##args)
#endif		/* __ENABLE_DEBUG__ */

#define CHECK(cond) ({											\
	int ___r = (cond);											\
	dbg_info("CHECK %s? \033[1m%s\033[0m\n", #cond,				\
			___r? "\033[32mtrue": "\033[31mfalse");				\
	___r;														\
})

#define PRINT(type, fmt, val)	({								\
	typeof(val) ___r = (val);									\
	dbg_info("PRINT %s: " fmt "\n", #val, (type)___r);			\
	___r;														\
})

#endif