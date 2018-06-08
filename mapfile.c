#include <windows.h>

DWORD map_file(char *file, int *buffer_address)
{
	HANDLE hFile = NULL, hFileMapping = NULL;
	
	if(INVALID_HANDLE_VALUE == (hFile = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)))
		return GetLastError();
	
	if(0 == (hFileMapping = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, NULL)))
		return GetLastError();
	
	if(0 == (*buffer_address = (int)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0)))
		return GetLastError();
	
	CloseHandle(hFile);
	CloseHandle(hFileMapping);
	
	return ERROR_SUCCESS;
}

int unmap_file(long int buffer_address)
{
	return UnmapViewOfFile((LPCVOID)buffer_address);
}
