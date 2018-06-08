#include <windows.h>

unsigned long get_file_size(char *file);
int calc_file_md5(char *file, char *md5);
int calc_buf_md5(BYTE *buf, unsigned long size, char *md5);
