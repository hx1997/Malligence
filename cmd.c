#include <stdio.h>
#include "Windows.h"

int cmd_echo(char *cmd, char *echo_buf, int bufsize)
{
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	
	HANDLE hRead = NULL, hWrite = NULL;
	DWORD bytesRead = 0;
	
	int fStatus = ERROR_SUCCESS;
	
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	
	if(!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		fStatus = GetLastError();
		return fStatus;
	}
	
	memset((void *)&si, 0, sizeof(STARTUPINFO));
    memset((void *)&pi, 0, sizeof(PROCESS_INFORMATION));
    
	GetStartupInfo(&si);
	si.cb = sizeof(STARTUPINFO);
	si.wShowWindow = SW_HIDE;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	
	if(!CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		fStatus = GetLastError();
		CloseHandle(hRead);
		CloseHandle(hWrite);
		return fStatus;
	}
	
	CloseHandle(hWrite);
	
	while(1) {
		if(FALSE == ReadFile(hRead, echo_buf, bufsize, &bytesRead, NULL))
			break;
	}
	
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hRead);
	
	return fStatus;
}

int system_wait(char *cmd)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	
	HANDLE hProcess = NULL;
	DWORD ret = 0;
	
	int fStatus = ERROR_SUCCESS;
	
	memset((void *)&si, 0, sizeof(STARTUPINFO));
    memset((void *)&pi, 0, sizeof(PROCESS_INFORMATION));
    
	GetStartupInfo(&si);
	si.cb = sizeof(STARTUPINFO);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW;
	
	if(!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		fStatus = GetLastError();
		return fStatus;
	}
	
	if(hProcess = OpenProcess(SYNCHRONIZE, FALSE, pi.dwProcessId)) {
		do {
			ret = WaitForSingleObject(hProcess, 0);
		} while(ret == WAIT_TIMEOUT);
		
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		
		return ret;
	}
	else {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		
		return GetLastError();
	}
}
