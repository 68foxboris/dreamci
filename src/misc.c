#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <errno.h>
#include "misc.h"
 
#ifndef BUF_SIZE    
#define BUF_SIZE 1024
#endif

extern int debug;
extern int quiet;
extern char authie[7];       
extern char devie[7];       
extern int  logging;
extern char logfile[256];

extern char ci_name[128];
 
#define IS_CTRL  (1 << 0)
#define IS_EXT	 (1 << 1)
#define IS_ALPHA (1 << 2)
#define IS_DIGIT (1 << 3)

// maximal 10 MB logfile at /tmp
#define MAXLOG 10240

extern int ci_number;
extern char ci_name_underscore[128];
 
unsigned int char_tbl[256] = {0};

/* stubs to get rid of dlopen linker errors */
void dlopen()
 {
 }
void dlsym()
 {
 }
void dlerror()
 {
 }
void dlclose()
 {
 }
void dladdr()
 {
 }
/* stubs to get rid of zlib */
void inflateInit_()
 {
 }
void deflateInit_()
 {
 }
void inflateEnd()
 {
 }
void deflateEnd()
 {
 }
void inflate()
 {
 }
void deflate()
 {
 }
void zError()
 {
 }

extern char *strcasestr(const char *haystack, const char *needle);

#define PROC_DIRECTORY "/proc/"
#define CASE_SENSITIVE    1
#define CASE_INSENSITIVE  0
#define EXACT_MATCH       1
#define INEXACT_MATCH     0

void reset_auth(int ci_number)
	{
        struct dirent *direntry;
        DIR *dir;

	fprintf(stdout, "[DCP] ERASING CI%d\n\n",ci_number);

        char cin[128];
	char source[256];
	char target[256];
	char sourcepath[256];
	char targetpath[256];
	char ending[256];
        char authpath[16];
        strcpy(authpath,"/etc/enigma2");

       	strcpy(cin,ci_name);
	FILE *auth_bin;
       	/* quickly replace blanks */
        int i=0;
        while (cin[i] != 0)
           {
           if (cin[i] == 32)
	       cin[i]= 95; 
       	   i++;
       	   };
        sprintf(source, "ci_auth_slot_%d.bin", ci_number);
        sprintf(sourcepath, "%s/%s", authpath, source);
	auth_bin = fopen(sourcepath, "r");
       	if (auth_bin)
       		{
		fclose(auth_bin);
		if (debug > 0) lprintf("CI%d REMOVES %s\n",ci_number,source);
		remove(sourcepath);
		}
        sprintf(target, "ci_auth_%s_%d.bin", cin, ci_number);
        sprintf(targetpath, "%s/%s", authpath, target);
	auth_bin = fopen(targetpath, "r");
       	if (auth_bin)
       		{
		fclose(auth_bin);
		if (debug > 0) lprintf("CI%d REMOVES %s\n",ci_number,target);
		remove(targetpath);
		}

       	if ((dir = opendir(authpath))) 
       		{
	        sprintf(ending,"_%d.bin",ci_number);
       		while ((direntry = readdir(dir)) != NULL)
           		{
           		if (!strncmp((*direntry).d_name,"ci_auth_",8))
				{
				if (strstr((*direntry).d_name,ending))
					{
		           		sprintf(target,"%s", (*direntry).d_name);
           				sprintf(targetpath,"%s/%s", authpath, target);
	   				if (debug > 0) lprintf("CI%d REMOVES %s\n",ci_number,target);
			   		remove(targetpath);
					}
           			}
           		}
        	closedir(dir);
		}

        if (quiet)
		{
                sprintf(authpath,"%s/%s", authie,devie);
                mkdir(authie, 0777);
                mount("/", authie, NULL, MS_BIND, NULL);
                mkdir(authpath, 0777);
	        target[0]=32;
       		if (ci_number==1)
                	{
         	        target[1]=32; /* "  " */
                	target[2]=0;
                	}
        	else
                	{
                	target[1]=0; /* " " */
                	}
        	sprintf(sourcepath, "%s/%s", authpath, target);
		remove(sourcepath);

                umount(authie);
                rmdir(authie);

	        strcpy(authpath,"/var/run/ca");
       		if ((dir = opendir(authpath))) 
           		{
        		while ((direntry = readdir(dir)) != NULL)
           			{
           			if (!strncmp((*direntry).d_name,"ci_auth_",8))
					{
					if (strstr((*direntry).d_name,ending))
						{
           					sprintf(target,"%s", (*direntry).d_name);
           					sprintf(targetpath,"%s/%s", authpath, target);
	   					if (debug > 0) lprintf("CI%d REMOVES %s\n",ci_number,target);
	   					remove(targetpath);
						}
           				}
           			}
     	   		closedir(dir);
			}
		}
	return;
	}


int file_opened(char *filename, pid_t pid)
{
     struct dirent *direntry;
     char procbuf[64];
     int opened=0;
     struct stat buf;
     char linkname[256];
     ssize_t ret_len;
     int buf_len;

     sprintf(procbuf, "/proc/%i/fd", pid);
     DIR *dir = opendir(procbuf);
     char links[64];
     buf_len=sizeof(linkname);
     while ((direntry = readdir(dir)) != NULL)
        {
        sprintf(links, "/proc/%i/fd/%s", pid,(*direntry).d_name);

        if (lstat(links, &buf) == 0)
                {
                ret_len=readlink(links, linkname, buf_len-1);
		if (ret_len != -1)
			linkname[ret_len]='\0';
                if (ret_len > 0)
                        {
                        /* found file as opened from process with pid */
                        if (!strcmp(filename,linkname))
                                {
                                opened=atol((*direntry).d_name);
                                }
                        }
                 }
        }
     closedir(dir);
     return opened;
}

int IsNumeric(const char* ccharptr_CharacterList)
        {
            for ( ; *ccharptr_CharacterList; ccharptr_CharacterList++)
                if (*ccharptr_CharacterList < '0' || *ccharptr_CharacterList > '9')
                    return 0; 
            return 1; 
        }

long strcmp_Wrapper(const char *s1, const char *s2, int intCaseSensitive)
        {
            if (intCaseSensitive)
                return !strcmp(s1, s2);
            else
                return !strcasecmp(s1, s2);
        }

long strstr_Wrapper(const char* haystack, const char* needle, int intCaseSensitive)
        {
	    int result;
            if (intCaseSensitive)
               result=(long) strstr(haystack, needle);
            else
                result=(long) strcasestr(haystack, needle);
	    return result;
        }

pid_t GetPIDbyName_implements(const char* cchrptr_ProcessName, int intCaseSensitiveness, int intExactMatch)
        {
            char chrarry_CommandLinePath[100]  ;
            char chrarry_NameOfProcess[300]  ;
            char* chrptr_StringToCompare = NULL ;
            pid_t pid_ProcessIdentifier = (pid_t) -1 ;
            struct dirent* de_DirEntity = NULL ;
            DIR* dir_proc = NULL ;

            long (*CompareFunction) (const char*, const char*, int) ;

            if (intExactMatch)
                CompareFunction = &strcmp_Wrapper;
            else
                CompareFunction = &strstr_Wrapper;


            dir_proc = opendir(PROC_DIRECTORY) ;
            if (dir_proc == NULL)
            {
  		if (debug > 0) lprintf("Couldn't open the " PROC_DIRECTORY " directory: %s\n",strerror(errno)); 
                return (pid_t) -2 ;
            }

            // Loop while not NULL
            while ( (de_DirEntity = readdir(dir_proc)) )
            {
                if (de_DirEntity->d_type == DT_DIR)
                {
                    if (IsNumeric(de_DirEntity->d_name))
                    {
                        strcpy(chrarry_CommandLinePath, PROC_DIRECTORY) ;
                        strcat(chrarry_CommandLinePath, de_DirEntity->d_name) ;
                        strcat(chrarry_CommandLinePath, "/cmdline") ;
                        FILE* fd_CmdLineFile = fopen (chrarry_CommandLinePath, "rt") ;  // open the file for reading text
                        if (fd_CmdLineFile)
                        {
			    // read from /proc/<NR>/cmdline
                            while (fscanf(fd_CmdLineFile, "%s", chrarry_NameOfProcess) != EOF)
				{
				if (debug > 10) lprintf("CMD %s\n",chrarry_NameOfProcess);
				}
                            fclose(fd_CmdLineFile);  // close the file prior to exiting the routine

                            if (strrchr(chrarry_NameOfProcess, '/'))
                                chrptr_StringToCompare = strrchr(chrarry_NameOfProcess, '/') +1 ;
                            else
                                chrptr_StringToCompare = chrarry_NameOfProcess ;

                            //printf("Process name: %s\n", chrarry_NameOfProcess);
                            //printf("Pure Process name: %s\n", chrptr_StringToCompare );

                            if ( CompareFunction(chrptr_StringToCompare, cchrptr_ProcessName, intCaseSensitiveness) )
                            {
                                pid_ProcessIdentifier = (pid_t) atoi(de_DirEntity->d_name) ;
                                closedir(dir_proc) ;
                                return pid_ProcessIdentifier ;
                            }
                        }
                    }
                }
            }
            closedir(dir_proc) ;
            return pid_ProcessIdentifier ;
        }

pid_t GetPIDbyName_Wrapper(const char* cchrptr_ProcessName, ... )
            {
                int intTempArgument ;
                int intInputArguments[2] ;
                // intInputArguments[0] = 0 ;
                // intInputArguments[1] = 0 ;
                memset(intInputArguments, 0, sizeof(intInputArguments) ) ;
                int intInputIndex ;
                va_list argptr;

                va_start( argptr, cchrptr_ProcessName );
                    for (intInputIndex = 0;  (intTempArgument = va_arg( argptr, int )) != 15; ++intInputIndex)
                    {
                        intInputArguments[intInputIndex] = intTempArgument ;
                    }
                va_end( argptr );
                return GetPIDbyName_implements(cchrptr_ProcessName, intInputArguments[0], intInputArguments[1]);
            }

#define GetPIDbyName(ProcessName,...) GetPIDbyName_Wrapper(ProcessName, ##__VA_ARGS__, (int) 15)

int copy_file(char *source, char *target)
{
     int inputFd, outputFd, openFlags;
     ssize_t numRead;
     char buf[BUF_SIZE];
     inputFd = open(source, O_RDONLY);
     if (inputFd == -1)
	{
        if (debug > 0) lprintf("%s error: %s\n",source, strerror(errno));   
	}
     openFlags = O_CREAT | O_WRONLY | O_TRUNC;
     if (!strstr(source,"choices"))
	{
        outputFd = open(target, openFlags, 0666);
        }
     else
	{
        outputFd = open(target, openFlags, 0444);
        }
     if (outputFd == -1)
	{
        if (debug > 0) lprintf("%s error: %s\n",target, strerror(errno));   
	}
     while ((numRead = read(inputFd, buf, BUF_SIZE)) > 0)
         if (write(outputFd, buf, numRead) != numRead)
		{
	        if (debug > 0) lprintf("%s error: %s\n",target, strerror(errno));   
		}
     if (numRead == -1)
	{
        if (debug > 0) lprintf("%s error: %s\n",source, strerror(errno));   
	}
     if (close(inputFd) == -1)
	{
        if (debug > 0) lprintf("%s error: %s\n",source, strerror(errno));   
	}
     if (close(outputFd) == -1)
	{
        if (debug > 0) lprintf("%s error: %s\n",target, strerror(errno));   
	}
     return 0;
}

int count_files(char *directory, char *starting)
	{
        struct dirent *direntry;
        DIR *dir;
	int found=0;
	int len=0;

	len=strlen(starting);
	if (len == 0)
		{
	        if (debug > 9) lprintf("CI%d FAILED %s\n", ci_number, directory);
		return found;
		}

        if ((dir = opendir(directory)) == NULL) 
           	{
	        if (debug > 9) lprintf("CI%d FAILED %s\n", ci_number, directory);
           	}
	else
           	{
	        while ((direntry = readdir(dir)) != NULL)
	           	{
		   	if (!strncmp((*direntry).d_name,starting,len))
				{
				found++;
				}
	           	}
	        closedir(dir);
           	}
	return found;
	}


#define MIN_STRING_SIZE 11
#define BUFFER_SIZE 16384

int check_enigma2()
{
FILE *inp;
size_t i, c_read;
char buf[MIN_STRING_SIZE+2];
char rbuf[BUFFER_SIZE];

inp = fopen("/usr/bin/enigma2", "rb");
if (inp <= 0) 
   {
   return 0;
   }

i = 0;
while ((c_read = fread(rbuf, 1, sizeof rbuf, inp)) > 0)
{
size_t k;
for (k=0; k < c_read; ++k) 
   {
   if (isprint(rbuf[k])) 
      {
      if (i < MIN_STRING_SIZE)
	 {
         buf[i] = rbuf[k];
	 }
      else if (i == MIN_STRING_SIZE) 
         {
	 buf[i+1]=0;
	 if (strstr(buf,"/var/run/c"))
		{
		fclose(inp);
		return 1;
		}
         }
      ++i;
      }
   else  /* not printable, reset search */
      {
      i = 0;
      }
   }
}
fclose(inp);
return 0;
}

/* write_name_file
 *
 * Writes the CI name file
 */

int write_name_file (char *name)
{
  FILE *f;
  char namefile[128];
  char ci[2];
  sprintf(namefile,"/var/run/ca/CI_%d_%s", ci_number+1, name);
  if (debug > 2) lprintf("CI%d WRITE name file CI_%d_%s\n", ci_number, ci_number+1, name);

  f = fopen(namefile, "a");
  if (f)
     {
     sprintf(ci, "%d\n", ci_number);
     fwrite(ci, strlen(ci), 1, f);
     fclose(f);
     }

  return 0;
}

/* remove_name_file
 *
 * Removes the CI name file
 */

int remove_name_file (char *name)
{
  FILE *f;
  char namefile[128];
  if (strlen(name) > 0)
	{
  	sprintf(namefile,"/var/run/ca/CI_%d_%s", ci_number+1, name);
  	if (debug > 9) lprintf("CI%d REMOVING name file CI_%d_%s\n", ci_number, ci_number+1, name);

  	if (!(f=fopen(namefile,"r")))
    	return 0;
  	fclose(f);
  	return unlink (namefile);
	}
   return 1;
}
  
/* could use ctypes, but then they pretty much do the same thing */
void init_strip_table()
{
	int i;
 
	for (i = 0; i < 32; i++) char_tbl[i] |= IS_CTRL;
	char_tbl[127] |= IS_CTRL;
 
	for (i = 'A'; i <= 'Z'; i++) {
		char_tbl[i] |= IS_ALPHA;
		char_tbl[i + 0x20] |= IS_ALPHA; /* lower case */
	}
 
	for (i = 128; i < 256; i++) char_tbl[i] |= IS_EXT;
}
 
/* depends on what "stripped" means; we do it in place.
 * "what" is a combination of the IS_* macros, meaning strip if
 * a char IS_ any of them
 */
void strip(char *str, int what)
{
	unsigned char *ptr, *s = (void*)str;
	ptr = s;
	while (*s != '\0') {
		if ((char_tbl[(int)*s] & what) == 0)
			*(ptr++) = *s;
		s++;
	}
	*ptr = '\0';
}

int write_input()
{
  FILE *f;

  if (debug > 4) lprintf("CI%d RESETS encoder\n",ci_number);
  char *input="/proc/stb/avs/0/input";
  f = fopen(input, "r+");
  if (f != NULL)
     {
     fprintf(f,"encode\n");
     fflush(f);
     fclose(f);
     return 0;
     }
  return 1;
}

int write_proc()
{
  FILE *f;

  int rmem_max=4194304;
  int wmem_max=4194304;
  int rmem_default=4194304;
  int wmem_default=4194304;
  int somaxconn=64;

  char *rmem_default_proc="/proc/sys/net/core/rmem_default";
  char *wmem_default_proc="/proc/sys/net/core/wmem_default";

  char *rmem_max_proc="/proc/sys/net/core/rmem_max";
  char *wmem_max_proc="/proc/sys/net/core/wmem_max";
  char *somaxconn_proc="/proc/sys/net/core/somaxconn";

  f = fopen(rmem_max_proc, "r+");
  if (f > 0)
	{
  	fprintf(f,"%d\n", rmem_max);
  	fclose(f);
	}

  f = fopen(wmem_max_proc, "r+");
  if (f > 0)
	{
  	fprintf(f,"%d\n", wmem_max);
	fclose(f);
	}

  f = fopen(rmem_default_proc, "r+");
  if (f > 0)
	{
  	fprintf(f,"%d\n", rmem_default);
  	fclose(f);
	}

  f = fopen(wmem_default_proc, "r+");
  if (f > 0)
	{
  	fprintf(f,"%d\n", wmem_default);
  	fclose(f);
	}

  f = fopen(somaxconn_proc, "r+");
  if (f > 0)
	{
  	fprintf(f,"%d\n", somaxconn);
  	fclose(f);
	}

  return 0;
}

int write_caid_file(char *caids)
{
  FILE *f;
  int fd;
  char caidfilename[32];
  sprintf(caidfilename,"/var/run/ca/ci%d.caid",ci_number);

  if ( ((fd = open(caidfilename, O_RDWR|O_CREAT, 0644)) == -1)
       || ((f = fdopen(fd, "r+")) == NULL) ) {
      if (debug > 0) lprintf("can't open or create %s\n", caidfilename);
      return 0;
  }
  if (!fprintf(f,"%s\n", caids)) {
      if (debug > 0) lprintf("can't write caids.\n");
      close(fd);
      return 0;
  }

  fflush(f);
  close(fd);
  if (debug > 8) lprintf("CI%d WRITING %s\n",ci_number, caidfilename);
  return 1;
}

int remove_caid_file()
{
  FILE *f;
  char caidfilename[32];
  sprintf(caidfilename,"/var/run/ca/ci%d.caid",ci_number);

  if (!(f=fopen(caidfilename,"r")))
    return 0;
  fclose(f);
  if (debug > 8) lprintf("CI%d REMOVING %s\n",ci_number, caidfilename);
  return unlink (caidfilename);
}

int check_caid_file()
{
  FILE *f;
  char caidfilename[32];
  sprintf(caidfilename,"/var/run/ca/ci%d.caid",ci_number);

  if (!(f=fopen(caidfilename,"r")))
    return 0;
  fclose(f);
  if (debug > 8) lprintf("CI%d FOUND %s\n",ci_number, caidfilename);
  return 1;
}

time_t get_mtime(const char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) == -1) {
	return 0;
    }
    return statbuf.st_mtime;
}

int get_random(unsigned char *dest, int len)
{
	int fd;
	char *urnd = "/dev/urandom";

	fd = open(urnd, O_RDONLY);
	if (fd <= 0) {
		if (debug > 0) lprintf("can not open %s\n", urnd);
		return -1;
	}

	if (read(fd, dest, len) != len) {
		if (debug > 8) lprintf("can not read from %s\n", urnd);
		close(fd);
		return -2;
	}

	close(fd);

	return len;
}

int parseLengthField(const unsigned char *pkt, int *len)
{
	int i;

	*len = 0;
	if (!(*pkt & 0x80)) {
		*len = *pkt;
		return 1;
	}
	for (i = 0; i < (pkt[0] & 0x7F); ++i) {
		*len <<= 8;
		*len |= pkt[i + 1];
	}
	return (pkt[0] & 0x7F) + 1;
}

int add_padding(uint8_t *dest, unsigned int len, unsigned int blocklen)
{
	uint8_t padding = 0x80;
	int count = 0;

	while (len & (blocklen - 1)) {
		*dest++ = padding;
		++len;
		++count;
		padding = 0;
	}

	return count;
}

static int get_bin_from_nibble(int in)
{
	if ((in >= '0') && (in <= '9'))
		return in - 0x30;

	if ((in >= 'A') && (in <= 'Z'))
		return in - 0x41 + 10;

	if ((in >= 'a') && (in <= 'z'))
		return in - 0x61 + 10;

	if (debug > 0) lprintf("fixme: unsupported chars in hostid\n");

	return 0;
}

void str2bin(uint8_t *dst, char *data, int len)
{
	int i;

	for (i = 0; i < len; i += 2)
		*dst++ = (get_bin_from_nibble(data[i]) << 4) | get_bin_from_nibble(data[i + 1]);
}

uint32_t UINT32(const unsigned char *in, unsigned int len)
{
	uint32_t val = 0;
	unsigned int i;

	for (i = 0; i < len; i++) {
		val <<= 8;
		val |= *in++;
	}

	return val;
}

int BYTE32(unsigned char *dest, uint32_t val)
{
	*dest++ = val >> 24;
	*dest++ = val >> 16;
	*dest++ = val >> 8;
	*dest++ = val;

	return 4;
}

int BYTE16(unsigned char *dest, uint16_t val)
{
	*dest++ = val >> 8;
	*dest++ = val;
	return 2;
}
