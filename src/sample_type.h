/******************************************************************************
 *   DTV LABORATORY, LG ELECTRONICS INC., SEOUL, KOREA
 *   Copyright(c) 1999 by LG Electronics Inc.
 *
 *   All rights reserved. No part of this work may be reproduced, stored in a
 *   retrieval system, or transmitted by any means without prior written
 *   permission of LG Electronics Inc.
 *****************************************************************************/

#ifndef SAMPLE_TYPE_H_
#define SAMPLE_TYPE_H_

/*-----------------------------------------------------------------------------
    Control Constants
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Include Headers
------------------------------------------------------------------------------*/

#include "stdio.h"
#include "stdlib.h"
#include "dirent.h"
#include "fcntl.h"
#include "string.h"
#include "unistd.h"
#include <pthread.h>
#include "json-c/json.h"

/*-----------------------------------------------------------------------------
	Constant Definitions
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Macro Definitions
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Type Definitions
------------------------------------------------------------------------------*/
#define JSON_ERROR(x) (!x)
#define JSON_PUT(x)   do {       \
		if (!JSON_ERROR(x)) {    \
			json_object_put(x);} \
		x = NULL;                \
} while (0)                      \



#ifndef UINT8
typedef unsigned char __UINT8;
	#define UINT8 __UINT8
#endif

#ifndef UINT08
typedef unsigned char __UINT08;
	#define UINT08 __UINT08
#endif

#ifndef SINT8
typedef signed char __SINT8;
	#define SINT8 __SINT8
#endif

#ifndef SINT08
typedef signed char __SINT08;
	#define SINT08 __SINT08
#endif

#ifndef CHAR
typedef char __CHAR;
	#define CHAR __CHAR
#endif

#ifndef UINT16
typedef unsigned short __UINT16;
	#define UINT16 __UINT16
#endif

#ifndef SINT16
typedef signed short __SINT16;
	#define SINT16 __SINT16
#endif

#ifndef UINT32
typedef unsigned int __UINT32;
	#define UINT32 __UINT32
#endif

#ifndef SINT32
typedef signed int __SINT32;
	#define SINT32 __SINT32
#endif

#ifndef BOOLEAN
	#ifndef _EMUL_WIN
typedef unsigned int __BOOLEAN;
		#define BOOLEAN __BOOLEAN
	#else
typedef unsigned char __BOOLEAN;
		#define BOOLEAN __BOOLEAN
	#endif
#endif

#ifndef ULONG
typedef unsigned long __ULONG;
	#define ULONG __ULONG
#endif

#ifndef SLONG
typedef signed long __SLONG;
	#define SLONG __SLONG
#endif

#ifndef UINT64
	#ifndef _EMUL_WIN
typedef unsigned long long __UINT64;
	#else
typedef unsigned _int64    __UINT64;
	#endif
	#define UINT64 __UINT64
#endif

#ifndef SINT64
	#ifndef _EMUL_WIN
typedef signed long long __SINT64;
	#else
typedef signed _int64    __SINT64;
	#endif
	#define SINT64 __SINT64
#endif

#ifndef TRUE
	#define TRUE (1)
#endif

#ifndef FALSE
	#define FALSE (0)
#endif

#ifndef NULL
	#define NULL ((void *)0)
#endif

/*-----------------------------------------------------------------------------
    Extern Variables & Function Prototype Declarations
------------------------------------------------------------------------------*/

#endif
