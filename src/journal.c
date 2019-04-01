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

#define MIN_STRING_SIZE 24 
#define BUFFER_SIZE 16384

extern int ci_number;
extern int debug;

 
int check_journal()
{
FILE *inp;
size_t i, c_read;
char buf[MIN_STRING_SIZE+2];
char rbuf[BUFFER_SIZE];
char journaldir[256];
char journalfile[256];
struct dirent *direntry;

char *directory="/run/log/journal";

DIR *dir;

dir = opendir(directory);
if (dir == NULL)
	{
        if (debug > 9) lprintf("CI%d FAILED OPEN %s\n", ci_number, directory);
	return 0;
        }
else
        {
        while ((direntry = readdir(dir)) != NULL)
              {
	      sprintf(journaldir, "/run/log/journal/%s", (*direntry).d_name);
              }
        closedir(dir);
        }
//if (debug > 9) lprintf("CI%d JOURNAL DIR %s\n", ci_number, journaldir);

sprintf(journalfile,"%s/system.journal",journaldir);

//if (debug > 9) lprintf("CI%d JOURNAL FILE %s\n", ci_number, journalfile);

inp = fopen(journalfile, "rb");

if (inp <= 0) 
   {
   if (debug > 9) lprintf("CI%d FAILED %s\n", ci_number, journalfile);
   return 0;
   }

i = 0;
int handler=0;
while ((c_read = fread(rbuf, 1, sizeof rbuf, inp)) > 0)
{
size_t k;
for (k=0; k < c_read; ++k) 
   {
   if (isprint(rbuf[k])) 
      {
      if (i <= MIN_STRING_SIZE)
	 {
         buf[i] = rbuf[k];
	 buf[i+1]=0;
         if (i == MIN_STRING_SIZE)
	    {
	    if (strstr(buf,"=new session"))
		{
//		if (debug > 9) lprintf("CI%d JOURNAL: %s\n", ci_number, buf);
		handler=atol(buf+23);
//		if (debug > 9) lprintf("CI%d HANDLER: %d\n", ci_number, handler);
		}
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
if (handler > 0)
	if (debug > 9) lprintf("CI%d JOURNAL HANDLER: %d\n", ci_number, handler);
return handler;
}

