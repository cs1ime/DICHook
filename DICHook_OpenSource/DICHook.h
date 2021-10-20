//author :cslime
//https://github.com/CS1ime/DICHook

#pragma once

#ifndef _SPOOFER_INCLUDED_
#define _SPOOFER_INCLUDED_

#include "ntifs.h"
#include "DDKCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

VOID setpcabk(PVOID fun);
VOID setdicpostcabk(PVOID func);
VOID setdicprecabk(PVOID func);
VOID setntqcabk(PVOID func);
VOID setntqhookstats(BOOL stats);

#ifdef __cplusplus
}
#endif

#endif // !_SPOOFER_INCLUDED_



