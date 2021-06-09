/******************************************************************************
 *   DTV LABORATORY, LG ELECTRONICS INC., SEOUL, KOREA
 *   Copyright(c) 1999 by LG Electronics Inc.
 *
 *   All rights reserved. No part of this work may be reproduced, stored in a
 *   retrieval system, or transmitted by any means without prior written
 *   permission of LG Electronics Inc.
 *****************************************************************************/

#ifndef A_SETTINGSERVICE_H_
#define A_SETTINGSERVICE_H_

#include "sample_type.h"
/*-----------------------------------------------------------------------------
    Control Constants
------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------
    File Inclusions
------------------------------------------------------------------------------*/

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
    Extern Variables & Function Prototype Declarations
------------------------------------------------------------------------------*/
BOOLEAN adapter_settingservice_register(void);
BOOLEAN adapter_settingservice_setSettingsservice(char *category, char *key, char *value);
BOOLEAN adapter_settingservice_setSettingsserviceBoolean(char *category, char *key, BOOLEAN value);
BOOLEAN adapter_settingservice_getLoadedInfo(void);

#endif/*_A_SYSTEMSERVICE_H_*/
