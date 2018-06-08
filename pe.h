struct pe_file {
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeaders;
	IMAGE_SECTION_HEADER *EPSections;
};

int read_pe(char *file, struct pe_file *pf);
int SystemTimeToTime_t(SYSTEMTIME *systemTime, time_t *dosTime);
int Time_tToSystemTime(time_t dosTime, SYSTEMTIME *systemTime);
