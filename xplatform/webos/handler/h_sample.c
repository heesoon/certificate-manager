/******************************************************************************
 *   DTV LABORATORY, LG ELECTRONICS INC., SEOUL, KOREA
 *   Copyright(c) 1999 by LG Electronics Inc.
 *
 *   All rights reserved. No part of this work may be reproduced, stored in a
 *   retrieval system, or transmitted by any means without prior written
 *   permission of LG Electronics Inc.
 *****************************************************************************/

/*-----------------------------------------------------------------------------
    Global Control Constants
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    File Inclusions
------------------------------------------------------------------------------*/
#include "lunaservice2.h"
#include "pmlog.h"

/*-----------------------------------------------------------------------------
    Constant Definitions
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Macro Definitions
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Type Definitions
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Extern Variables & External Function Prototype Declarations
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Define global variables
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    Static Variables & Function Prototypes Declarations
------------------------------------------------------------------------------*/
static bool handler_sample_sampleRun(LSHandle *sh, LSMessage *message , void *ctx);

LSMethod default_methods[] = {
	{"samplerun", 	handler_sample_sampleRun, 0},
	{NULL, NULL}
};

/*-----------------------------------------------------------------------------
    Implementation of static and global functions
------------------------------------------------------------------------------*/
static bool handler_sample_sampleRun(LSHandle* lshandle, LSMessage *message, void *ctx)
{
	LSError lserror;
	bool ret;
	struct json_object *jobj = NULL;

	LSMessageRef(message);

EXIT:

	jobj = json_object_new_object();

	json_object_object_add(jobj, "returnValue", json_object_new_boolean(TRUE));
	json_object_object_add(jobj, "result", json_object_new_string("service alive!"));
	
	PMLOG_INFO(MSGID_LS2_RECEIVED_INFO, "%s: received sampleRun", __FUNCTION__);

	LSErrorInit(&lserror);	

	ret = LSMessageReply(lshandle, message, json_object_to_json_string(jobj), &lserror);

	if (!ret)
	{
		LSErrorPrint(&lserror, stderr);
		LSErrorFree(&lserror);
	}

	json_object_put(jobj);
	LSMessageUnref(message);

	return ret;
}
