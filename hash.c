#include <string.h>
#include <windows.h>
#include <Wincrypt.h>
#include "mapfile.h"

unsigned long get_file_size(char *file)
{
    HANDLE hFile = CreateFile(file, FILE_READ_EA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    
	if (hFile != INVALID_HANDLE_VALUE)
	{
		unsigned long size = GetFileSize(hFile, NULL);
		CloseHandle(hFile);
		
		return size;
	}
	
	return 0;
}

int calc_buf_md5(BYTE *buf, unsigned long size, char *md5)
{
	BYTE *r_hash; DWORD hash_len = 0; DWORD hash_len_size = sizeof(DWORD);
	HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
	char md5_str[33] = {0};
	int i = 0;
	
	if(!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return 1;
	
	if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		return 1;
	
	if(!CryptHashData(hHash, buf, size, 0))
		return 1;
	
	if(!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&hash_len, &hash_len_size, 0))
		return 1;
	
	if((r_hash = (BYTE *)malloc(hash_len)))
		if(!CryptGetHashParam(hHash, HP_HASHVAL, r_hash, &hash_len, 0))
			return 1;
	
	for(; i < hash_len; i++)
	{
		char hex_char[3];
		itoa(r_hash[i], hex_char, 16);
		
		if(hex_char[1] == '\0') {
			md5_str[i*2] = '0';
			md5_str[i*2+1] = hex_char[0];
		}
		else {
			md5_str[i*2] = hex_char[0];
			md5_str[i*2+1] = hex_char[1];
		}
	}
	
	strncpy(md5, md5_str, 33);
	
	return 0;
}

int calc_file_md5(char *file, char *md5)
{
	BYTE *buf = 0; unsigned long size = 0;
	char md5_str[33] = {0};
	
	size = get_file_size(file);
	
	if(ERROR_SUCCESS == map_file(file, (int *)&buf))
	{
		calc_buf_md5(buf, size, md5_str);
		
		unmap_file((long int)buf);
		
		strncpy(md5, md5_str, 33);
	}
	
	return 0;
}
