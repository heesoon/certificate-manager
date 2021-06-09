/******************************************************************************
 *   DTV LABORATORY, LG ELECTRONICS INC., SEOUL, KOREA
 *   Copyright(c) 1999 by LG Electronics Inc.
 *
 *   All rights reserved. No part of this work may be reproduced, stored in a
 *   retrieval system, or transmitted by any means without prior written
 *   permission of LG Electronics Inc.
 *****************************************************************************/

/*-----------------------------------------------------------------------------
    (Global Control Constants)
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    (File Inclusions)
------------------------------------------------------------------------------*/
#include "lunaservice2.h"
#include "lunaservice.h"
#include "json.h"
/*-----------------------------------------------------------------------------
    (Constant Definitions)
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    (Macro Definitions)
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    (Type Definitions)
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    (Extern Variables & External Function Prototype Declarations)
------------------------------------------------------------------------------*/
extern LSMethod default_methods[];

/*-----------------------------------------------------------------------------
    (Define global variables)
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    (Static Variables & Function Prototypes Declarations)
------------------------------------------------------------------------------*/
static LS_SERVICE_CATEGORY_T _methodCategory[] = {
	{"/",				default_methods},
	{NULL,  		    NULL}
};

static LSHandle* _m_handle = NULL;

static GMainLoop* _gpstMainLoop        = NULL;

static void* _lunaservice2_handleloop(void *data);

/*-----------------------------------------------------------------------------
    (Implementation of static and global functions)
------------------------------------------------------------------------------*/
/**
 * get private handle
*/
LSHandle* sample_lunaservice2_getMainHandle(void)
{
	return _m_handle;
}

/**
 * run main event loop to handle lunaservice
 * 
 */
static void* _lunaservice2_handleloop(void *data)
{
	g_main_loop_run(_gpstMainLoop);
	return NULL;
}


/**
 * start luna service with new thread
 */
gboolean sample_lunaservice2_startService()
{
	if (_gpstMainLoop == NULL)
	{
		return false;
	}
	g_thread_new("sample_lunaservice2", _lunaservice2_handleloop, NULL);
	return true;
}


/**
 * register service name, category name and methods
  */
gboolean sample_lunaservice2_registerService(const char *name)
{
	LSHandle              *lsHandle    = NULL;
	LSError                lserror;
	LS_SERVICE_CATEGORY_T *pCategories = NULL;

	if (_gpstMainLoop == NULL)
	{
		_gpstMainLoop = g_main_loop_new(NULL, FALSE);
	}

	LSErrorInit(&lserror);

	// BEGIN REGISTERING PRIVATE HANDLE
	if (!_m_handle)
	{
		if (!LSRegister(name, &_m_handle, &lserror))
		{
			_m_handle = NULL;
			goto ERROR;
		}
		if (!LSGmainAttach(_m_handle, _gpstMainLoop, &lserror))
		{
			goto ERROR;
		}
		lsHandle = _m_handle;
	}
	else
	{
		lsHandle = _m_handle;
	}

	pCategories = _methodCategory;
	while (pCategories->szCartegory != NULL)
	{
		if (!LSRegisterCategory(lsHandle, pCategories->szCartegory, pCategories->pMethods, NULL, NULL, &lserror))
		{
			goto ERROR;
		}

		pCategories++;
	}
	// END  REGISTERING PRIVATE HANDLE

	return true;

ERROR:
	if (LSErrorIsSet(&lserror))
	{
		LSErrorPrint(&lserror, stdout);
		LSErrorFree(&lserror);
	}
	return false;
}
