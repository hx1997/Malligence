#include <stdio.h>
#include <windows.h>
#include "pe.h"

int read_pe(char *file, struct pe_file *pf)
{
	int fStatus = 1;
	FILE *fp = fopen(file, "rb");
	
	fread(&pf->DosHeader, 1, sizeof(IMAGE_DOS_HEADER), fp);
	
	if(pf->DosHeader.e_lfanew) {
		fseek(fp, pf->DosHeader.e_lfanew, SEEK_SET);
		
		fread(&pf->NtHeaders, 1, sizeof(IMAGE_NT_HEADERS), fp);
		
		if(IMAGE_NT_SIGNATURE == pf->NtHeaders.Signature) {
			fStatus = 0;
			
			pf->EPSections = (IMAGE_SECTION_HEADER *)calloc(pf->NtHeaders.FileHeader.NumberOfSections, sizeof(IMAGE_SECTION_HEADER));
			fseek(fp, (pf->DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
			fread(pf->EPSections, sizeof(IMAGE_SECTION_HEADER), pf->NtHeaders.FileHeader.NumberOfSections, fp);
		}
	}
	
	fclose(fp);
	
	return fStatus;
}

// http://blogs.msdn.com/b/joshpoley/archive/2007/12/19/date-time-formats-and-conversions.aspx with modifications
int SystemTimeToTime_t(SYSTEMTIME *systemTime, time_t *dosTime)
{
    LARGE_INTEGER jan1970FT = {0};
    jan1970FT.QuadPart = 116444736000000000ll; // january 1st 1970
    LARGE_INTEGER utcFT = {0};

    SystemTimeToFileTime(systemTime, (FILETIME*)&utcFT);
    unsigned __int64 utcDosTime = (utcFT.QuadPart - jan1970FT.QuadPart)/10000000;
    *dosTime = (time_t)utcDosTime;
	
	return 0;
}

int Time_tToSystemTime(time_t dosTime, SYSTEMTIME *systemTime)
{
    LARGE_INTEGER jan1970FT = {0};
    jan1970FT.QuadPart = 116444736000000000ll; // january 1st 1970
    LARGE_INTEGER utcFT = {0};
    
    utcFT.QuadPart = ((unsigned __int64)dosTime)*10000000 + jan1970FT.QuadPart;
    FileTimeToSystemTime((FILETIME*)&utcFT, systemTime);
	
	return 0;
}
