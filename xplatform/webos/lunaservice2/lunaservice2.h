/******************************************************************************
 *   DTV LABORATORY, LG ELECTRONICS INC., SEOUL, KOREA
 *   Copyright(c) 1999 by LG Electronics Inc.
 *
 *   All rights reserved. No part of this work may be reproduced, stored in a
 *   retrieval system, or transmitted by any means without prior written
 *   permission of LG Electronics Inc.
 *****************************************************************************/
#ifndef _LUNASERVICE2_H_
#define _LUNASERVICE2_H_

/*-----------------------------------------------------------------------------
    (Control Constants)
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    (File Inclusions)
------------------------------------------------------------------------------*/
#include "lunaservice.h"

#ifdef  __cplusplus
extern "C"
{
#endif/* __cplusplus */

/*-----------------------------------------------------------------------------
    (Constant Definitions)
------------------------------------------------------------------------------*/


/*-----------------------------------------------------------------------------
    (Macro Definitions)
------------------------------------------------------------------------------*/


/*-----------------------------------------------------------------------------
    (Type Definitions)
------------------------------------------------------------------------------*/
typedef struct _LS_SERVICE_CATEGORY_T
{
	const char *szCartegory;
	LSMethod   *pMethods;
} LS_SERVICE_CATEGORY_T;

/*-----------------------------------------------------------------------------
    (Extern Variables & Function Prototype Declarations)
------------------------------------------------------------------------------*/
LSHandle* sample_lunaservice2_getMainHandle(void);
gboolean  sample_lunaservice2_registerService(const char *name);
gboolean  sample_lunaservice2_startService(void);

#ifdef  __cplusplus
}
#endif/* __cplusplus */
#endif/*_LUNASERVICE2_H_*/
