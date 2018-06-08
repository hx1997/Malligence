#define CURL_STATICLIB

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

int download_url(char *url, char *save_to, char *proxy)
{
	CURL *curl;
  	CURLcode res;
  	FILE *fp = fopen(save_to, "wb");
  	int status = 0;
  	
	if(!curl_global_init(CURL_GLOBAL_DEFAULT)) {
		curl = curl_easy_init();
  		if(curl) {
  			curl_easy_setopt(curl, CURLOPT_URL, url); // set URL
		    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp); // set save location
		    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
		    curl_easy_setopt(curl, CURLOPT_PROXY, proxy); // set proxy
		    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10); // set timeout to 10s
		    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 1048576); // set max file size to 1MB
		    
		    res = curl_easy_perform(curl);
		    if(res != CURLE_OK) {
		      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		      status = res;
			}
		    
		    curl_easy_cleanup(curl);
		}
	}
	
	fclose(fp);
	
	return status;
}

int URL2DomainName(const char *URL, char *DomainName)
{
	int i = 0;
	
	if(NULL == strstr(URL, "http://")) {
		for(i = 0; i < strlen(URL); i++) {
			if(URL[i] != '/') DomainName[i] = URL[i];
			else break;
		}
	}
	else {
		for(i = 7; i < strlen(URL); i++) {
			if(URL[i] != '/') DomainName[i - 7] = URL[i];
			else break;
		}
	}
	
	return 0;
}
