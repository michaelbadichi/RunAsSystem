
// RunAsSystem - main.cpp - by Michael Badichi

#include "stdafx.h"
#include "RunAsSystem.h"

#include <sstream>
#include <string>
#include <vector>
#include <stdlib.h>

#define DLOG 0

#define SSTR( x ) dynamic_cast< std::wostringstream & >( ( std::wostringstream() << std::dec << x ) ).str()

#pragma warning (disable:4996)

std::wstring AsWideString( const std::string& s )
{
    size_t mbSize = s.size() + 1;
    size_t wcSize = mbstowcs( 0, s.c_str(), mbSize ) + 1;
    std::vector< wchar_t > w( wcSize, 0 );
    mbstowcs( &w[0], s.c_str(), mbSize );
    return std::wstring( &w[0] );
}

int __stdcall WinMain( __in HINSTANCE hInstance, __in_opt HINSTANCE hPrevInstance, __in_opt LPSTR lpCmdLine, __in int nShowCmd )
{
    DWORD retCode = 0;
    //skip whitespace
    while( lpCmdLine[0]==' ') lpCmdLine++;
    if( strlen( lpCmdLine ) == 0 )
    {
        MessageBox( NULL, L"usage: RunAsSystem  [--block] <cmdline>", L"RunAsSystem", MB_OK );
        MessageBeep( MB_ICONWARNING );
    }
    else
    {
        DWORD * pRetcode = NULL;
        if( strstr( lpCmdLine, "--block" ) == lpCmdLine ) {
            lpCmdLine += 8;
            pRetcode = &retCode;
            while( lpCmdLine[0]==' ') lpCmdLine++;
        }

        std::wstring cmd = AsWideString( std::string( lpCmdLine ) );
        const WCHAR * runFromDir = NULL;    //can be empty - in which case - use my dir

        bool ok = RunAsSystem( cmd.c_str(), runFromDir, pRetcode ); //if we dont provide retCode pointer, function dont wait for process to finish

#if DLOG
        std::wstring log = L"RunAsSystem --> '";
        log += cmd;
        log += L"' --> ";
        log += (ok ? L"ok" : L"FAIL" );
        if( ok ) 
        {
            log += SSTR( " ==> " << retCode );
        }
        OutputDebugString( log.c_str() );
#endif
    }
    return (int)retCode;
}

#ifdef _CONSOLE

int main( int argc, char ** argv ) 
{
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPSTR lpCmdLine = GetCommandLineA();
    LPSTR pCmdLine = lpCmdLine;
    if( *pCmdLine == '"' ) {
        char * p = strstr( pCmdLine+1, "\"" );
        if( p ) {
            p++;
            while( *p == ' ' ) p++;
            pCmdLine = p;
        }
    } 
    else 
    {
        while( char * p = strstr( pCmdLine, " " ) ) {
            if( p > pCmdLine && *(p-1) != '\\' ) {
                pCmdLine = p+1;
                break;
            }
            pCmdLine = p+1;
        }
    }
    if( pCmdLine == lpCmdLine ) pCmdLine = "";
    return WinMain( hInstance, NULL, pCmdLine, SW_SHOWNORMAL );
}

#endif
