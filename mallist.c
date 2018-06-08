#include <stdio.h>
#include <string.h>
#include "net.h"

#define BUFSIZE 512

#define fuck(a) printf("%s\n", a);

int dl_vx()
{
	FILE *fp1 = NULL, *fp2 = NULL, *fp3 = NULL;
	char url[BUFSIZE] = {0};
	char foo[BUFSIZE] = {0};
	char bar[BUFSIZE] = {0};
	
	// download VX list
	if(!download_url("http://vxvault.siri-urz.net/URL_List.php", "VX.txt", GAE)) {
		fp1 = fopen("VX.txt", "r");
		if(NULL == fp1) return 1;
		
		while(NULL != fgets(url, BUFSIZE, fp1)) {
			if(!strncmp(url, "http://", 7)) { // if URL starts with "http://"
				fp2 = fopen("download_url.txt", "a"); // add it to the download list
				fputs(url, fp2);
				fclose(fp2);
				
				memset(foo, 0, BUFSIZE);
				URL2DomainName(url, foo);
				
				if(!strcmp(foo, bar)) continue;
				
				memset(bar, 0, BUFSIZE);
				strncpy(bar, foo, BUFSIZE);
				
				memset(url, 0, BUFSIZE);
				sprintf(url, "curl -s -o.\\VT.txt https://www.virustotal.com/en/domain/%s/information/", foo);
				
				if(!system_wait(url)) {
					fp3 = fopen("VT.txt", "r");
					if(NULL == fp3) return 1;
					
					while(NULL != fgets(foo, BUFSIZE, fp3)) {
						if(!strncmp(foo, "      http://", 13)) {
							fp2 = fopen("download_url.txt", "a"); // add it to the download list
							fputs(foo + 6, fp2);
							fclose(fp2);
						}
					}
					
					fclose(fp3);
				}
			}
		}
		
		fclose(fp1);
	}
	
	remove("VX.txt");
	remove("VT.txt");
	
	return 0;
}

int dl_murls()
{
	FILE *fp1 = NULL, *fp2 = NULL;
	char url[BUFSIZE] = {0};
	char foo[BUFSIZE] = {0};
	
	// download MURLs list
	if(!download_url("http://malwareurls.joxeankoret.com/normal.txt", "MURLs.txt", "")) {
		fp1 = fopen("MURLs.txt", "r");
		if(NULL == fp1) return 1;
		
		while(NULL != fgets(url, BUFSIZE, fp1)) {
			if(!strncmp(url, "http://", 7)) { // if URL starts with "http://"
				if(strncmp(strrev(url), "\nmoc.", 5) && strncmp(strrev(url), "\nten.", 5) \
				&& strncmp(strrev(url), "\nur.", 4)  && strncmp(strrev(url), "\nku.", 4)  \
				&& strncmp(strrev(url), "\ngro.", 5) && strncmp(strrev(url), "\nofni.", 6)) {  // exclude URLs which end in ".com", ".net", ".ru", ".uk", ".org", and ".info"
					fp2 = fopen("download_url.txt", "a"); // add it to the download list
					fputs(url, fp2);
					fclose(fp2);
				}
			}
		}
		
		fclose(fp1);
	}
	
	remove("MURLs.txt");
	
	return 0;
}

int dl_mdl()
{
	FILE *fp1 = NULL, *fp2 = NULL;
	char url[BUFSIZE] = {0};
	
	// download MDL
	if(!download_url("http://www.malwaredomainlist.com/hostslist/yesterday_urls.php", "MDL.txt", "")) {
		fp1 = fopen("MDL.txt", "r");
		if(NULL == fp1) return 1;
		
		while(NULL != fgets(url, BUFSIZE, fp1)) {
			fp2 = fopen("download_url.txt", "a"); // add it to the download list
			fputs(url, fp2);
			fclose(fp2);
		}
		
		fclose(fp1);
	}
	
	remove("MDL.txt");
	
	return 0;
}

int dl_mbl()
{
	FILE *fp1 = NULL, *fp2 = NULL;
	char url[BUFSIZE] = {0};
	
	// download MBL
	if(!download_url("http://www.malwareblacklist.com/mbl.xml", "MBL.txt", "")) {
		fp1 = fopen("MBL.txt", "r");
		if(NULL == fp1) return 1;
		
		while(NULL != fgets(url, BUFSIZE, fp1)) {
			int p = (int)strstr(url, "Host: ");
			char tmp[BUFSIZE] = {0};
			
			if(0 != p) {
				strncpy(tmp, (char *)p + 6, (int)strstr(url, ",") - p - 6);
				strncat(tmp, "\n", 1);
				
				fp2 = fopen("download_url.txt", "a"); // add it to the download list
				fputs(tmp, fp2);
				fclose(fp2);
			}
		}
		
		fclose(fp1);
	}
	
	remove("MBL.txt");
	
	return 0;
}

int dl_malc0de()
{
	FILE *fp1 = NULL, *fp2 = NULL;
	char url[BUFSIZE] = {0};
	
	// download Malc0de
	if(!download_url("http://malc0de.com/rss/", "Malc0de.txt", GAE)) {
		fp1 = fopen("Malc0de.txt", "r");
		if(NULL == fp1) return 1;
		
		while(NULL != fgets(url, BUFSIZE, fp1)) {
			int p = (int)strstr(url, "URL: ");
			char tmp[BUFSIZE] = {0};
			
			if(0 != p) {
				strncpy(tmp, (char *)p + 5, (int)strstr(url, ",") - p - 5);
				strncat(tmp, "\n", 1);
				
				fp2 = fopen("download_url.txt", "a"); // add it to the download list
				fputs(tmp, fp2);
				fclose(fp2);
			}
		}
		
		fclose(fp1);
	}
	
	remove("Malc0de.txt");
	
	return 0;
}
