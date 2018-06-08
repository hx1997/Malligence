#include <stdio.h>
#include <tchar.h>

#include "cmd.h"
#include "net.h"
#include "mallist.h"
#include "hash.h"
#include "pe.h"
#include "adobe_malware_classifier.h"
#include "log.h"

#define BUFSIZE 512

int check_whitelist(char *imphash_arg)
{
	char imphash_file[33] = {0};
	FILE *fp = fopen("whitelist.txt", "r"); // open the list of URL to download from
	
	while(NULL != fgets(imphash_file, 33, fp))
		if(!strncmp(imphash_arg, imphash_file, 33)) {
			fclose(fp);
			return 1;
		}
	
	fclose(fp);
	return 0;
}

// return value: 0 - OK; 1 - No Imphash; 2 - Whitelisted
int classify_imphash(char *md5, char *url)
{
	char buf[4096] = {0};
	char cmd_line[MAX_PATH] = "K:\\Python27\\python.exe .\\imphash-gen.py -p \".\\samples\"";
	char imphash[33] = {0};
	char tmp_cmd[MAX_PATH] = {0};
	
	if(!cmd_echo(cmd_line, buf, 4095))
	{
		if(strstr(buf, md5) != NULL) {
			if(strstr(buf, "IMP:  MD5:") != NULL) {
				sprintf(tmp_cmd, "if not exist .\\samples\\Unclassified\\%s.exe copy .\\samples\\%s.exe .\\samples\\Unclassified\\%s.exe", md5, md5, md5);
				system(tmp_cmd);
				memset(tmp_cmd, 0, MAX_PATH);
				sprintf(tmp_cmd, "del .\\samples\\%s.exe", md5);
				system(tmp_cmd);
			
				log_metadata_itw("Unclassified", md5, url);
				
				return 1;
			}
			
			strncpy(imphash, strstr(buf, md5) - 38, 32);
			
			if(check_whitelist(imphash)) {
				printf("Whitelisted. Deleting...\n");
				sprintf(tmp_cmd, "del .\\samples\\%s.exe", md5);
				system(tmp_cmd);
				
				return 2;
			}
			
			sprintf(tmp_cmd, "md .\\samples\\%s", imphash);
			system(tmp_cmd);
			sprintf(tmp_cmd, "if not exist .\\samples\\%s\\%s.exe copy .\\samples\\%s.exe .\\samples\\%s\\%s.exe", imphash, md5, md5, imphash, md5);
			system(tmp_cmd);
			memset(tmp_cmd, 0, MAX_PATH);
			sprintf(tmp_cmd, "del .\\samples\\%s.exe", md5);
			system(tmp_cmd);
			
			log_metadata_itw(imphash, md5, url);
		}
	}
	
	return 0;
}

int classify_samples(char *path, char *url)
{
	char md5[33] = {0};
	char ren_cmd[76] = {0};
	
	char tmp_cmd[MAX_PATH] = {0};
	char buf[4096] = {0};
	
	struct pe_file pf;
	memset(&pf, 0, sizeof(pf));
	
	// see if downloaded file is a PE
	if(read_pe(path, &pf)) {
		// Non-PE, delete
		printf("Non-PE. Deleting...\n");
		remove(path);
		return 1;
	}
	
	// see if downloaded file is compiled lately (within 1 day from now)
	SYSTEMTIME st = {0};
	time_t tt = 0;
	GetSystemTime(&st);
	SystemTimeToTime_t(&st, &tt);
	
	if(pf.NtHeaders.FileHeader.TimeDateStamp >= 0x386CD300 && pf.NtHeaders.FileHeader.TimeDateStamp < tt - 0x15180) {
		printf("Obsolete. Deleting...\n");
		remove(path);
		return 1;
	}
	
	// see if downloaded file is clean
	//if(runAll(path) != 1) {
	//	printf("Clean. Deleting...\n");
	//	remove(path);
	//	return 1;
	//}
	
	// see if downloaded file is digitally-signed
	sprintf(tmp_cmd, ".\\sigcheck.exe -e -q \"%s\"", path);
	
	if(!cmd_echo(tmp_cmd, buf, 4095))
	{
		if(strstr(buf, "Signed") != NULL) {
			printf("Digitally signed. Deleting...\n");
			remove(path);
			return 1;
		}
	}
	
	// file over 1MB, unlikely to be malicious
	if(get_file_size(path) >= 1048576) {
		printf("File size greater than 1MB. Deleting...\n");
		remove(path);
		return 1;
	}
	
	calc_file_md5(path, md5);
	sprintf(ren_cmd, "ren \"%s\" %s.exe", path, md5); // rename to MD5 filename
	
	// rename failed, delete
	if(system(ren_cmd)) {
		remove(path);
		return 1;
	}
	else {
		printf("Success: %s\n", md5);
		classify_imphash(md5, url);
	}
	
	return 0;
}

int download_samples()
{
	char url[BUFSIZE] = {0}, path[256] = {0}, domain[68] = {0}, foo[68] = {0};
	int n = 0, times_of_failure = 0;
	
	FILE *fp = fopen("download_url.txt", "r"); // open the list of URL to download from
	
	while(NULL != fgets(url, BUFSIZE, fp)) {
		sprintf(path, ".\\samples\\%d.exe", n);
		
		URL2DomainName(url, foo);
		
		if(!strcmp(foo, domain) && times_of_failure >= 4) {
			printf("%d Temporarily avoiding invalid URL: %s\n", n, url);
			continue;
		}
		else if(strcmp(foo, domain))
			times_of_failure = 0;
		
		printf("%d Downloading: %s", n, url);
		
		if(!download_url(url, path, "")) { // download from the specified URL
			// success
			if(!classify_samples(path, url))
				n++;
			else {
				memset(foo, 0, 68);
				URL2DomainName(url, foo);
				if(!strcmp(foo, domain)) times_of_failure++;
				memset(domain, 0, 68);
				URL2DomainName(url, domain);
			}
		}
		else if(!download_url(url, path, GAE)) {
			// success with GAE
			if(!classify_samples(path, url))
				n++;
			else {
				memset(foo, 0, 68);
				URL2DomainName(url, foo);
				if(!strcmp(foo, domain)) times_of_failure++;
				memset(domain, 0, 68);
				URL2DomainName(url, domain);
			}
		}
		else {
			remove(path); // delete if failed
			
			memset(foo, 0, 68);
			URL2DomainName(url, foo);
			if(!strcmp(foo, domain)) times_of_failure++;
			memset(domain, 0, 68);
			URL2DomainName(url, domain);
		}
		
		puts("");
	}
	
	fclose(fp);
	remove("download_url.txt");
	
	return 0;
}

int main()
{
Fetch:
	remove("download_url.txt");
	printf("Fetching malicious URL list...\n\n");
	
	dl_mbl();
	download_samples();
	
	dl_mdl();
	download_samples();
	
	dl_vx();
	download_samples();
	
	dl_malc0de();
	download_samples();
	
	dl_murls();
	download_samples();
	
	printf("Download complete. Checking again in 15 mins.\n\n");
	Sleep(900000);
	goto Fetch;
	
	return 0;
}
