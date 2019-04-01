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
 
extern int debug;
extern int fifo;
extern int fifo_named;
extern int fifo_call;
extern int fifo_handler;
extern int fifo_request;
extern time_t fifo_time;   
extern char cdev[10];
extern char pdev[16];
extern char ci_name[128];
extern int ci_number;
extern int max_ci;

/* this is just a minimal app info CI resource implementation
   for the fifo device which tells enigma2 the module name */
 
int create_fifo()
  {
  FILE *f;

  struct stat fifo_stat;
  stat(cdev, &fifo_stat);  
  if (S_ISFIFO(fifo_stat.st_mode)) {                            
  	if (debug > 4) lprintf("CI%d FIFO PIPE %s exists\n",ci_number, cdev);
	return 0;
	}
  if ((f=fopen(pdev,"r")))
        {
        fclose(f);
        }
  else
  	{
  	if (debug > 4) lprintf("CI%d MOVE %s -> %s\n",ci_number, cdev, pdev);
        rename(cdev,pdev);
        }
  if ((f=fopen(cdev,"r")))
        {
        fclose(f);
        }
  else 
  	{
   	/* create the FIFO (named pipe) */
  	if (debug > 4) lprintf("CI%d FIFO PIPE %s created\n",ci_number, cdev);
    	mkfifo(cdev, 0777);
	}
  return 1;
  }

int open_fifo()
{
if (fifo > 0) return 1;
fifo = open(cdev, O_RDWR | O_NONBLOCK | O_CLOEXEC );
if (fifo < 0)
        {
        fprintf(stdout, "\n   FIFO PIPE FAILED CI%d: %s %s\n", ci_number, cdev, strerror(errno));
	return 0;
	}
return 1;
}

int name_fifo(int enable)
 {
 if (fifo_handler || fifo_named)
	{
	return 0; /* means it already finished */
	}
  else
	{
        if (debug > 9) lprintf("CI%d NAME FIFO PIPE APP CALL #%d\n", ci_number,fifo_call);
	fifo_named=1;
        fifo_call=0;                                                
        fifo_request=0;                                              
	}

 if (!fifo)
	{
 	int ret=open_fifo();
 	if (!ret)
		{
		if (debug > 9) lprintf("OPEN FIFO PIPE APP FAILED\n");
		return 0;
		}
	}

 init_fifo_app();

 while(fifo_handler==0)  
        {                                        
        read_fifo();                                           
//	if (fifo_handler==0)
//	       	fifo_handler=check_journal(); 
        fifo_call++;                                         
        if (fifo_handler > 0)                                   
                {                                                     
                write_fifo(enable);              
                }    
        }                             
// close_fifo(0);
 return 1;
 }                             

int init_fifo_app()
	{
//	if (debug > 9) lprintf("INIT FIFO PIPE APP %s\n", cdev);
	char   request[6]; /* request application manager resource */
	int req_len=6;
        int ret=0;
	request[0]=0x91;
	request[1]=0x04;
	request[2]=0x00;
	request[3]=0x02;
	request[4]=0x00;
	request[5]=0x41; /* always report as CI 1.0 !!! */
// 	Message: 91 04 00 02 00 41
//      if (debug > 6) lprintf("WRITE FIFO PIPE DATA len %d\n",req_len);
//      if (debug > 9) hexdump((const uint8_t *)request,req_len);
	ret=write(fifo, request, req_len);
	if (ret > 0)
		{
		fifo_call++;
		fifo_request++;
		}
	return 1;
	}

int init_fifo_mmi()
	{
//	if (debug > 9) lprintf("INIT FIFO PIPE MMI %s\n", cdev);
	char   request[6]; /* request application manager resource */
	int req_len=6;
        int ret=0;
	request[0]=0x91;
	request[1]=0x04;
	request[2]=0x00;
	request[3]=0x40;
	request[4]=0x00;
	request[5]=0x41; /* always report as CI 1.0 !!! */
// 	Message: 91 04 00 40 00 41
//      if (debug > 6) lprintf("WRITE FIFO PIPE DATA len %d\n",req_len);
//      if (debug > 9) hexdump((const uint8_t *)request,req_len);
	ret=write(fifo, request, req_len);
	if (ret > 0)
		fifo_call++;
	sync();
        return 1;
	}

int read_fifo()
	{
  	if (!fifo) open_fifo();
	fifo_call++;
//	if (debug > 9) lprintf("RECEIVED FIFO PIPE CALL #%d\n", fifo_call);
	ssize_t count;
	char buf[512];
	int i;
        count = read (fifo, buf, sizeof(buf));
	if (count == 6) /* we just have read or own request from fifo */
		{
		if (fifo_request > 0)
			fifo_request--;
		}
	else if (count > 6)
		{
		if (debug > 9) 
			{
			lprintf("RECEIVED FIFO PIPE data lenght %d\n",count);
			hexdump((const uint8_t *)buf, count);
			}
		if (count !=8) /* just reply from enigma2 */
		    {
		    for (i = 0; i < (count-4); i++)
			{
			if (buf[i]==0x02 && buf[i+1]==0x00 && buf[i+2]==0x41 && buf[i+3]==0x0)
				{
				fifo_handler=buf[i+4];
				if (fifo_handler==0) fifo_handler=255;
				}
			}
		    if (fifo_handler==0) /* no handler data read */
			if (fifo_request > 0)
				fifo_request--;
		    }
		}
	if (fifo_handler > 0) 
		{
		if (debug > 9) lprintf("CI%d FIFO PIPE HANDLER %d FROM REQUEST #%d\n", ci_number,fifo_handler,fifo_request);
		fifo_time=time(NULL);
		check_journal();
		}
	else    /* play it again ... */
		{
		if (fifo_request < 16) /* new request needed */
			{
			init_fifo_app();
			}
		else                   /* brute force */             
			{
			fifo_handler=check_journal();
			if (fifo_handler == 0)
				{
				fifo_handler=5*max_ci+ci_number;
				}
			fifo_time=time(NULL);
			if (debug > 9) lprintf("CI%d FIFO PIPE HANDLER %d FROM TOO MANY REQUESTS\n", ci_number,fifo_handler);
			}
		}
	return 1;
	}

int write_fifo(int enable)
  { /* just reply with the name of the Module when enabled, 
       or only with CI 1 or CI 2 when disabled */

  /* without fifo handler session it is useless to talk */
  if (!fifo_handler) return 0; 

  if (!fifo) open_fifo();

  int namelen=0;
  char buffer[37];
  int count=0;

  if (enable)
	{
  	namelen=strlen(ci_name);
  	if (namelen > 22) namelen=22;
	}
  else
	{
  	namelen=4; /* only CI 1 or CI 2 */
	}
  buffer[0]=0x90;
  buffer[1]=0x02;
  buffer[2]=0x00;
  buffer[3]=fifo_handler;
  buffer[4]=0x9f;
  buffer[5]=0x80;
  buffer[6]=0x21;
#ifdef OLD
  buffer[7]=namelen+11; /* length of CI 1 or CI 2 plus Module Name */
#else
  buffer[7]=27; 	 /* length of maximal Module Name */
#endif
  buffer[8]=0x01;
  buffer[9]=0x00;
  buffer[10]=0x00;
  buffer[11]=0x00;
  buffer[12]=0x00;
  buffer[13]=0x15;
  if (enable)
	{
	buffer[14]=0x20;
	buffer[15]=0x20;
	buffer[16]=0x20;
	buffer[17]=0x20;
	}
  else
	{
	buffer[14]=0x43;
	buffer[15]=0x49;
	buffer[16]=0x20;
	buffer[17]=ci_number+49;
	}
  buffer[18]=0x20;
  buffer[19]=0x20;
  buffer[20]=0x20;
  buffer[21]=0x20;
  buffer[22]=0x20;
  buffer[23]=0x20;
  buffer[24]=0x20;
  buffer[25]=0x20;
  buffer[26]=0x20;
  buffer[27]=0x20;
  buffer[28]=0x20;
  buffer[29]=0x20;
  buffer[30]=0x20;
  buffer[31]=0x20;
  buffer[32]=0x20;
  buffer[33]=0x20;
  buffer[34]=0x20;
  buffer[35]=0x20;
  buffer[36]=0;

  if (enable)
	{
#ifdef OLD
	strncpy(buffer+19,ci_name,namelen);
#else
	strncpy(buffer+14,ci_name,namelen);
#endif
	if (debug > 9) lprintf("CI%d FIFO PIPE FEEDING HANDLER %d: %s\n",ci_number, fifo_handler, ci_name);
	fifo_named=1;
	}
  else
	{
	if (debug > 9) lprintf("CI%d FIFO PIPE FEEDING HANDLER %d: CI %d\n",ci_number, fifo_handler, ci_number+1);
	fifo_named=0;
	}

  /* write the data to the FIFO */
#ifdef OLD
  hexdump((const uint8_t *) buffer,namelen+19);
  write(fifo, buffer, namelen+19);
  if (count < (namelen+19))
#else
  hexdump((const uint8_t *) buffer,35);
  count=write(fifo, buffer, 35);
  if (count < 35 && count > 0)
#endif
	{
	if (debug > 9) lprintf("CI%d FIFO PIPE wrote only %d bytes\n",ci_number, count);
	return 0;
	}
   return 1;
}

int close_fifo(int forced)
  {
  FILE *f;
  struct stat fifo_stat;
  stat(cdev, &fifo_stat);  
  if (S_ISFIFO(fifo_stat.st_mode)) {                            
  	if (debug > 4) lprintf("CI%d FIFO PIPE already %s\n",ci_number, cdev);
	/* fifos are persistent, so if not forced we don't remove */
        close(fifo);
  	if (!forced) return 1;
	}
  f=fopen(pdev,"r");
  if (f) /* if exists rename plus device back */
     {
     fclose(f);
     if (debug > 4) lprintf("CI%d FIFO PIPE removing %s\n",ci_number, pdev);
     /* remove the FIFO just to make sure - could crash enigma2 */
//   unlink(cdev);   
     rename(pdev,cdev);
     }
  return 1;
  }
