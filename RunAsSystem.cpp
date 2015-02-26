
// RunAsSystem - RunAsSystem.cpp - by Michael Badichi


#include <Windows.h>
#include <Ntsecapi.h>
#include <Psapi.h>
#include <UserEnv.h>
#include <LMCons.h>
#include <Shlwapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "Psapi")
#pragma comment (lib, "UserEnv")
#pragma comment (lib, "Shlwapi")

template< typename T > std::wstring toString( const T& value )
{
    std::wstringstream oss;
    oss << value;
    return oss.str();
}
typedef std::auto_ptr< SID > SidPtr_t;

SidPtr_t _LookupAccountName( std::wstring sName, std::wstring sSystem )
{
    DWORD cbSid = 0;
    DWORD cbDomain = 0;
    SID_NAME_USE tSid;
    LookupAccountName( sSystem.c_str(), sName.c_str(), NULL, &cbSid, NULL, &cbDomain, &tSid );
    if( cbSid != 0 )
    {
        SID * pSid = (SID *)new char[ cbSid ];
        std::vector<WCHAR> domain( cbDomain );
        if( LookupAccountName( sSystem.c_str(), sName.c_str(), pSid, &cbSid, &domain[0], &cbDomain, &tSid ) )
        {
            return SidPtr_t( pSid );
        }
    }

    return SidPtr_t(NULL);
}

LSA_HANDLE _LsaOpenPolicy( ACCESS_MASK iAccess )
{
    LSA_OBJECT_ATTRIBUTES lsaAttr = {0};
    LSA_HANDLE hPolicy;
    if( SUCCEEDED( LsaOpenPolicy( NULL, &lsaAttr, iAccess, &hPolicy ) ) )
    {
        return hPolicy;
    }
    return INVALID_HANDLE_VALUE;
}

bool _LsaAddAccountRights( std::wstring sName, std::wstring sRight )
{
    bool retCode = false;
    std::wstring domain;
    SidPtr_t sid = _LookupAccountName( sName, L"" );
    SID * pSid = sid.get();
    if( IsValidSid( pSid ) )
    {
        LSA_HANDLE hPolicy = _LsaOpenPolicy( 0x811 );
        if( hPolicy != INVALID_HANDLE_VALUE )
        {
            int iLen = sRight.length() * 2;
            std::vector< WCHAR > tRight( iLen );
            wcscpy_s( &tRight[0], iLen, sRight.c_str() );
            LSA_UNICODE_STRING unicode;
            unicode.Length = iLen;
            unicode.MaximumLength = iLen + 2;
            unicode.Buffer = &tRight[0];
            if( SUCCEEDED( LsaAddAccountRights( hPolicy, pSid, &unicode, 1 ) ) )
            {
                retCode = true;
            }
            LsaClose( hPolicy );
        }
        retCode = true;
    }
    return retCode;
}

bool _SetPrivilege( std::wstring Privilege )
{
    bool retCode = false;
    HANDLE curProc = GetCurrentProcess();
    HANDLE hToken;
    if( OpenProcessToken( curProc, TOKEN_ALL_ACCESS, &hToken ) )
    {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue( L"", Privilege.c_str(), &tp.Privileges[0].Luid );
        TOKEN_PRIVILEGES tpout;
        DWORD retLen = 0;
        BOOL stat = AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(tpout), &tpout, &retLen );
        DWORD lasterr = GetLastError();
        if( lasterr  != 0)
        {
            //OutputDebugString( (std::wstring(L"AdjustTokenPrivilefes(")+Privilege+L") :"+toString(lasterr)).c_str() );
            if( lasterr == ERROR_NOT_ALL_ASSIGNED ) 
            {
                WCHAR uname[ UNLEN+1 ];
                DWORD cbUname = sizeof( uname ) / sizeof( uname[0] );
                if( GetUserName( uname, &cbUname ) )
                {
                    if( _LsaAddAccountRights( uname, Privilege ) )
                    {
                        OutputDebugString( (std::wstring(L"Reboot required for changes to take effect: ")+Privilege).c_str() );
                        stat = TRUE;
                    }
                    else
                    {
                        OutputDebugString( (std::wstring(L"Error: The right was probably not added correctly to your account: ")+Privilege).c_str() );
                        stat = FALSE;
                    }
                }
            }
        }
        CloseHandle( hToken );
        retCode = ( stat == TRUE );
    }
    return retCode;
}

bool IsProcessIdMatchingName( DWORD processID, std::wstring name )
{
    bool retCode = false;
    WCHAR szProcessName[ MAX_PATH ] = L"<unknown>";
    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID );
    if ( hProcess )
    {
        WCHAR path[ MAX_PATH + FILENAME_MAX + 1];
        if( GetProcessImageFileName( hProcess, path, sizeof( path ) / sizeof( path[0] ) ) )
        {
            WCHAR * fname = StrRChr( path, NULL, L'\\' );
            if( fname )
            {
                fname++;
                //OutputDebugString( (std::wstring(L"Testing process name ")+fname).c_str() );
                retCode = ( _wcsicmp( fname, name.c_str() ) == 0 );
            }
        }
        CloseHandle( hProcess );
    }
    else
    {
        //OutputDebugString((std::wstring(L"Error opening process ID ")+toString(processID)).c_str());
    }
    return retCode;
}

DWORD GetProcessIdByName( std::wstring name, DWORD sessionID )
{
    DWORD retCode = 0;
    DWORD aProcesses[16*1024];
    DWORD cbNeeded;
    unsigned int i;
    if ( EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
        DWORD cProcesses = cbNeeded / sizeof(DWORD);
        for ( i = 0; i < cProcesses; i++ )
        {
            if( aProcesses[i] != 0 )
            {
                //OutputDebugString( (std::wstring(L"Testing process ID ")+toString(aProcesses[i])).c_str() );
                if( IsProcessIdMatchingName( aProcesses[i], name ) )
                {
                    DWORD sesID = 0;
                    if( ProcessIdToSessionId( aProcesses[i], &sesID ) )
                    {
                        if( sesID == sessionID )
                        {
                            //found it
                            retCode = aProcesses[i];
                            break;
                        }
                    }
                }
            }
        }
    }
    return retCode;
}

VOID * _GetEnvironmentBlock( DWORD processID )
{
    VOID * retCode = NULL;

	HANDLE hProc = OpenProcess( 0x02000000, FALSE, processID );
    if( hProc )
    {
        HANDLE hToken;
        if( OpenProcessToken( hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken ) )
        {
            if( CreateEnvironmentBlock( &retCode, hToken, TRUE ) )
            {
                //yey
            }
            CloseHandle( hToken );
        }
        CloseHandle( hProc );
    }
    return retCode;
}



bool RunAsSystem( const WCHAR * cmd_, const WCHAR * runFromDir_, DWORD * procDoneRetCode_ = NULL )
{
	std::wstring cmd = cmd_ ? cmd_ : L"";
	std::wstring runFromDir = runFromDir_ ? runFromDir_ : L"";
    bool retCode = false;
    WCHAR * winlogon = L"winlogon.exe";
    WCHAR * privileges[] = {
        L"SeDebugPrivilege",
        L"SeAssignPrimaryTokenPrivilege",
        L"SeIncreaseQuotaPrivilege"
    };
    for( int i=0; i<sizeof(privileges)/sizeof(privileges[0]); i++ ) {
        _SetPrivilege( privileges[i] );
    }
    DWORD sessionID = WTSGetActiveConsoleSessionId();
    if( sessionID != 0xFFFFFFFF )
    {
        DWORD processId = GetProcessIdByName( winlogon, sessionID );
        if( processId )
        {
            HANDLE hProc = OpenProcess( 0x001F0FFF, FALSE, processId );
            if( hProc != NULL )
            {
                HANDLE hToken;
                if( OpenProcessToken( hProc, TOKEN_DUPLICATE, &hToken ) )
                {
                    HANDLE hDupToken;
                    if( DuplicateTokenEx( hToken, 0x001F0FFF, NULL, SecurityIdentification, TokenPrimary, &hDupToken ) )
                    {
                        VOID * envBlock = _GetEnvironmentBlock( processId );
                        DWORD createFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
                        if( envBlock ) createFlags |= CREATE_UNICODE_ENVIRONMENT;
                        STARTUPINFO si = {0};
                        PROCESS_INFORMATION pi = {0};
                        si.cb = sizeof( si );
                        si.lpDesktop = L"winsta0\\default";

                        typedef BOOL (WINAPI *CreateProcessWithTokenW_proto) ( HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
                        CreateProcessWithTokenW_proto CreateProcessWithTokenW_fn = NULL;
                        HMODULE hMod = LoadLibrary( L"ADVAPI32.dll" );
                        if( hMod ) 
                        {
                            CreateProcessWithTokenW_fn = (CreateProcessWithTokenW_proto)GetProcAddress( hMod, "CreateProcessWithTokenW" );
                        }

                        if( CreateProcessWithTokenW_fn == NULL || !CreateProcessWithTokenW_fn( hDupToken, LOGON_WITH_PROFILE, NULL, (LPWSTR)cmd.c_str(), createFlags, envBlock, runFromDir.empty() ? NULL : runFromDir.c_str(), &si, &pi ) )
                        {
                            //failed crating with token, try create as user
                            if( !CreateProcessAsUserW( hDupToken, NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE, createFlags, envBlock, runFromDir.empty() ? NULL : runFromDir.c_str(), &si, &pi ) )
                            {
                                //failed calling as user
                            }
                            else
                            {
                                retCode = true;
                            }
                        }
                        else
                        {
                            retCode = true;
                        }

                        if( retCode && procDoneRetCode_ != NULL ) 
                        {
                            WaitForSingleObject( pi.hProcess, INFINITE );
                            GetExitCodeProcess( pi.hProcess, procDoneRetCode_ );
                        }

                        if( hMod )
                        {
                            FreeLibrary( hMod );
                        }

                        if( envBlock )
                        {
                            DestroyEnvironmentBlock( envBlock );
                        }
                        CloseHandle( hDupToken );
                    }
                    CloseHandle( hToken );
                }
				else
				{
					//error opening process token
					MessageBox( NULL, toString(GetLastError()).c_str(), L"biii",MB_OK );
				}
                CloseHandle( hProc );
            }
        }
    }
	return retCode;
}
