#include <stdio.h>
#include <windows.h>

#include "pe.h"

#define BUFSIZE 512

int log_metadata_itw(const char *imphash, const char *md5, const char *url)
{
	char app_path[MAX_PATH] = {0}, ini_path[MAX_PATH] = {0}, foo[BUFSIZE] = {0}, bar[BUFSIZE] = {0};
	time_t current_time = 0; SYSTEMTIME st = {0};
	
	// set ini_path
	GetCurrentDirectory(MAX_PATH, app_path);
	sprintf(ini_path, "%s\\samples\\%s\\metadata.ini", app_path, imphash);
	
	// read "First seen" key
	sprintf(foo, "ITW_%s", md5);
	GetPrivateProfileString(foo, "First seen", NULL, bar, BUFSIZE, ini_path);
	
	// get current time (for first seen or last seen)
	time(&current_time);
	Time_tToSystemTime(current_time, &st);
	
	// is it first seen?
	if(!strcmp(bar, "")) {
		sprintf(bar, "%d/%d/%d %d:%d:%d UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		
		// foo = first seen, bar = now
		if(!WritePrivateProfileString(foo, "First seen", bar, ini_path))
			return 1;
		else {
			// bar = url
			memset(bar, 0, BUFSIZE);
			sprintf(bar, "%s", url);
		}
	}
	else
	{
		memset(bar, 0, BUFSIZE);
		sprintf(bar, "%d/%d/%d %d:%d:%d UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		
		// foo = last seen, bar = now
		if(!WritePrivateProfileString(foo, "Last seen", bar, ini_path))
			return 1;
		else {
			// is previous url the same as this one?
			if(!strcmp(bar, url)) {
				// bar = url
				memset(bar, 0, BUFSIZE);
				sprintf(bar, "%s", url);
			}
			else {
				// bar = bar & url
				memset(bar, 0, BUFSIZE);
				sprintf(bar, "%s | %s", bar, url);
			}
		}
	}
	
	// foo = download urls, bar = url
	if(!WritePrivateProfileString(foo, "Download URLs", bar, ini_path))
		return 1;
	
	return 0;
}

