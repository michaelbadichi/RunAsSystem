
// RunAsSystem - main.h - by Michael Badichi

#pragma once
#include <Windows.h>

bool RunAsSystem( const WCHAR * cmd, const WCHAR * runFromDir, DWORD * procDoneRetCode_ = NULL );
