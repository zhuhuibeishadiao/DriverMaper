#pragma once
#include "Pch.h"

NTSTATUS LeiLeiInitLdrData(IN PVOID pLdr);

NTSTATUS LeiLeiMMapDriver(IN PGLOBAL_INFO pInfo);

//PGLOBAL_INFO LeiLeiInitLoadDriver();