#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>
#include <sys/utsname.h>  
#include <errno.h>

#include "misc.h"

extern char old_buf_tuner[8];
extern char old_buf_device[32];
extern char old_buf_module[8];
extern char oldpids[256];
extern int  unicable;
extern int  max_ci;

extern int descrambles;
extern int ci_number;
extern int debug;
int justplay=0;
extern int current;

/* lets make more stuff global */
char name[256];
char provider[256];
extern char cachedpids[256];
char dvbnamespace[10];
char empty[256];
char serviceref[64];
char servfile[64];
char other_servfile[64];
extern char ci_name[128];
extern char ci_name_underscore[128];
extern char fullserviceref[64];
extern char currentref[64];

/* possible values for multicrypt */
#define NO 0
#define YES 1
#define AUTO 2

#define PROC_DIRECTORY "/proc/"
#define CASE_SENSITIVE    1
#define CASE_INSENSITIVE  0
#define EXACT_MATCH       1
#define INEXACT_MATCH     0

char *replace_str(char *str, char *orig, char *rep)
{
  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig))) {
	  // Is 'orig' even in 'str'?
	  return str;
  } 

  strncpy(buffer, str, p-str); // Copy characters from 'str' start to 'orig' st$
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

  return buffer;
}

void remove_service_file()
	{
	int ret;
   	FILE *service_file;
        sprintf(servfile,"/var/run/ca/ci%d.service",ci_number);
	service_file = fopen(servfile, "r");
	currentref[0]=0;
	if (service_file)
		{
		fclose(service_file);
		if (debug > 9) lprintf("CI%d REMOVING %s\n", ci_number,servfile);
		ret=remove(servfile);
		if (ret)
			{
	   		if (debug > 0) lprintf("%s error: %s\n",servfile, strerror(errno)); 
			}
		}
	}


int check_other(char *checkref)
	{
   	FILE *other_service_file;
	long fsize;

	/* nothing to check */
	if (strlen(checkref) == 0) return 0;
	if (max_ci < 2) return 0;

	if (debug >9) lprintf("CI%d CHECK channel: %s\n", !ci_number, checkref);

        sprintf(other_servfile,"/var/run/ca/ci%d.service",!ci_number);
	other_service_file = fopen(other_servfile, "r");
	if (other_service_file)
		{
		fseek(other_service_file, 0, SEEK_END);
		fsize = ftell(other_service_file);
		fseek(other_service_file, 0, SEEK_SET);
		/* read current channel from file of other module */
		char *string = malloc(fsize + 1);
		if (fread(string, fsize, 1, other_service_file) < 1)
			{
			if (debug >9) lprintf("read current channel failed\n");
			}
			
		fclose(other_service_file);
		string[fsize] = 0;
		/* checking channel */ 
		if (strstr(string,checkref) !=0) 
			{
			if (debug >1) lprintf("CI%d HANDLES channel: %s %s\n", !ci_number,checkref,name);
			free(string);
			return 1;
	    		}
		free(string);
    		}
	return 0; 
    	}

static int check_service()
	{
   	FILE *xml;
	long fsize;
   	char checker[32];
   	char xmlprovider[128];
	/* get ci module assignments */
	sprintf(checker,"/etc/enigma2/ci%d_%s.xml",ci_number, ci_name_underscore);

	if (debug > 9) lprintf("CI%d assignment xml: %s\n",ci_number, checker);
	xml=fopen(checker, "r");
        if (!xml) 
	    { /* try classic ci?.xml name */
	    sprintf(checker,"/etc/enigma2/ci%d.xml",ci_number);
	    xml=fopen(checker, "r");
            if (!xml) /* no assignment file means we accept everything */
	       {      
	       return 1;
    	       }
    	   }

	fseek(xml, 0, SEEK_END);
	fsize = ftell(xml);
	fseek(xml, 0, SEEK_SET);

	/* read ci assignment */
	char *string = malloc(fsize + 1);
	if (fread(string, fsize, 1, xml) < 1)
		{
		if (debug >9) lprintf("read ci assignment failed\n");
		}
	fclose(xml);
	string[fsize] = 0;
	if (debug > 9) lprintf("CI%d assignment: %s xml content:\n%s\n", ci_number, fullserviceref, string);

	if (strstr(string,fullserviceref) !=0) 
		{
		if (debug > 0) lprintf("CI%d ASSIGNED channel: %s\n", ci_number, name);
		free(string);
		return 1;
    		}

	sprintf(xmlprovider,"provider name=\"%s\" dvbnamespace=\"%s\"",provider,dvbnamespace);
//	sprintf(xmlprovider,"provider name=\"%s\" dvbnamespace=",provider);
	if (strstr(string,xmlprovider) !=0) 
		{
		if (debug > 0) lprintf("CI%d ASSIGNED channel: %s via provider: %s dvbnamespace: %s\n", ci_number, name, provider, dvbnamespace);
		free(string);
		return 1;
    		}

	if (debug > 9) lprintf("CI%d NOT ASSIGNED channel: %s\n", ci_number,name);
	free(string);
	return 0;
    	}

int save_service_file(int recording, int streaming)
	{
   	FILE *service_file;
        sprintf(servfile,"/var/run/ca/ci%d.service",ci_number);

	/* remember as active service reference */
        strcpy(currentref,fullserviceref);

	if (debug > 9) lprintf("SAVE full serviceref: %s\n", fullserviceref);
	if (debug > 9) lprintf("SAVE channel:         %s\n", name);
	if (debug > 9) lprintf("SAVE provider:        %s\n", provider);
	if (debug > 9) lprintf("CI%d WRITING %s\n",ci_number,servfile);
	service_file = fopen(servfile, "w+");
	if (service_file)
	   {
   	   fprintf(service_file,"%s\n%s\n%s\n", fullserviceref , name, provider );
	   if (recording) fprintf(service_file,"RECORDING\n");
	   if (streaming) fprintf(service_file,"STREAMING\n");
	   fclose(service_file);
           }
	else
	   {
	   if (debug > 0) lprintf("%s error: %s\n",servfile, strerror(errno)); 
           }
        return 0;
      }

int get_service(char  *sid, char *tsid, char *onid, char *dvbns)
	{
	char hdf[3];
	char *tmp="";
//	if (debug > 8) lprintf("passed: %s:%s:%s:%s\n",sid,tsid,onid,dvbns);

	/* from here we have to check lamedb again 
   	   to get servieref channel name and provider */
	int services=0;
	int i, matches;
	int sub=0;
	int pids=1;
	int pidlen=0;
	char *pidstarts;
	char *pidends;
	char line[256];
	const char *filename = "/etc/enigma2/lamedb";
	FILE *lamedb = fopen(filename, "r");
	const char *s = ":"; // ascii 58
	const char *k = ","; // ascii 44
	char *token;
	while (fgets(line, sizeof(line), lamedb)) 
		{
		/* lamedb beginns with transponders */
		if (strncmp(line,"services",8) == 0) 
			{
			services=1;
			}
		if (services) 
			{
			/* now it gets interesting */ 
//			printf("service: %s", line); 
			/* get the first token */
			token = strtok(line, s);
			/* walk through tokens */
			i=0;
   			matches=0; 
			hdf[0]=0;
   			while( token != NULL ) 
				{
//				printf( "token!sid:!%s!%s!", token,sid );
   				if ((i==0) && (strcmp(token,sid) == 0)) 
					{
   					matches++;
   					}
   				if ((i==1) && (strcmp(token,dvbns) == 0)) 
					{ 
   					matches++;
   					}
   				if ((i==2) && (strcmp(token,tsid) == 0)) 
					{ 
					matches++;
   					}
      				if ((i==3) && (strcmp(token,onid) == 0)) 
					{
					matches++;
      					}
   				if (i==4) 
					{ 
					/* hex 1  or decimal 1 is SD 
					   hex 16 or decimal 22 is SD with MPEG4
					   hex 19 or decimal 25 is HD */
					sprintf(hdf,"%02x", (unsigned int) atol(token));        
   					}
      				token = strtok(NULL, s);
      				i++;
      				}
      			if (matches>3) /* we found the service reference 
				  now get channel name and provider */
				{
				// needs optimization ...
				strcpy(serviceref,line);
 	     			if (!fgets(name, sizeof(name), lamedb)) 
					{
			   		if (debug > 0) lprintf("%s read error: %s\n",filename, strerror(errno)); 
					}
				name[strlen(name)-1]=0;
				strip(name, IS_CTRL | IS_EXT);
				/* workaround for subchannels */
				provider[0]=44;
				cachedpids[0]=0;
				while (provider[0]==44 || provider[0]==10)
				   {
				   /* provider always starts with p:X...
				      but if X is comma or line feed then it is 
                                      maybe a subchannel */
		         	   if (!fgets(provider,3,lamedb)) 
					{
			   		if (debug > 0) lprintf("%s read error: %s\n",filename, strerror(errno)); 
					}
 		        	   if (!fgets(provider,sizeof(provider),lamedb)) 
					{
			   		if (debug > 0) lprintf("%s read error: %s\n",filename, strerror(errno)); 
					}
				   if (pids == 1)
					{
					pidstarts=strstr(provider,",c:");
					pidends=strstr(provider,",C:");
					if ((pidstarts !=0) && (strlen(pidstarts) > 0))
						{
						if ((pidends !=0) && (strlen(pidends) > 0))
						   {
						   pidlen=pidends-pidstarts;
						   }	
						strncpy(cachedpids,pidstarts,pidlen);
						cachedpids[pidlen]=0;  
						/* remove all ,c: */
						while (strstr(cachedpids,",c:") !=0) 
							{
							tmp=replace_str(cachedpids,",c:"," ");
							strcpy(cachedpids,tmp);
							}
//							tmp=cachedpids+1;
//							strcpy(cachedpids,tmp);
						}
					pids = 0;
					}
				
 		        	   if (!fgets(empty,sizeof(empty),lamedb)) 
					{
			   		if (debug > 0) lprintf("%s read error: %s\n",filename, strerror(errno)); 
					}
 		        	   if (!fgets(empty,sizeof(empty),lamedb)) 
					{
			   		if (debug > 0) lprintf("%s read error: %s\n",filename, strerror(errno)); 
					}
				   }
   				token = strtok(provider, k);
//				strcpy(provider,token);
				sprintf(provider,"%s",token);

				/* remove linefeed */
				int ll=strlen(provider)-1;
				if (provider[ll]==10) provider[ll]=0;

				if (debug > 9) lprintf("hdf:    %s\n",hdf);
				/* workaround for select channels */
				if (strncmp(hdf,"d3",2) == 0)
				 	{
					sub=1;
					sprintf(serviceref,":1:%s:%s:%s:%s:",sid,tsid,onid,dvbns);
					}
				else
				 	{
					sub=0;
					sprintf(serviceref,":%s:%s:%s:%s:%s:",hdf,sid,tsid,onid,dvbns);
					}
				/* remove leading 0 */
				while (strstr(serviceref,":0") !=0) 
					{
					tmp=replace_str(serviceref,":0",":");
					strcpy(serviceref,tmp);
					}
				/* make uppercase */
				int i;
				i=0;
				while(serviceref[i]) {
				    	serviceref[i]=(toupper(serviceref[i]));
    					i++;
					}

				/* dvbnamespace is also needed for correct
                                   provider detection */
				strcpy(dvbnamespace,dvbns);
				/* remove leading 0 */
				while (dvbnamespace[0]==48) 
					{
					i=0;
					while(dvbnamespace[i]) {
						dvbnamespace[i]=(dvbnamespace[i+1]);
						i++;
						}
					}
				/* make uppercase */
				i=0;
				while(dvbnamespace[i]) {
				    	dvbnamespace[i]=(toupper(dvbnamespace[i]));
    					i++;
   					}
   				}
   			}
    		}
	fclose(lamedb);
	if (sub)
		{
		/* workaround for subchannels */
		sprintf(fullserviceref,"1:0%s12:4:0:",serviceref);
		}
	else
		{
		sprintf(fullserviceref,"1:0%s0:0:0:",serviceref);
		}
	if (debug > 3) lprintf("full serviceref: %s\n", fullserviceref);
	if (debug > 3) lprintf("channel:         %s\n", name);
	if (debug > 3) lprintf("provider:        %s\n", provider);

      return 0;
      }

void push_old()
    {
    FILE *f;
    char buf_device[64];
    char buf_tuner[8];
    const char used_ci[] = "/proc/stb/tsmux/ci%d_input";
    snprintf(buf_device, sizeof(buf_device), used_ci, ci_number);
    /* getting tuner which the module uses currently */
    f = fopen(buf_device, "r");
    if (fread(buf_tuner, sizeof(buf_tuner), 1, f) < 1)
	{
	if (debug >9) lprintf("read current tuner failed\n");
	}
    fclose(f);
//  if (debug > 9) lprintf("CI%d PUSH: %s <- %s\n",ci_number, buf_device, buf_tuner);
    /* use last demux to write it back, so that we don't get sid in pat error */
    if ((strstr(buf_tuner,old_buf_tuner)!=0) && (strlen(old_buf_device) > 0))
 	{
	if (debug > 9) lprintf("CI%d OLD tuner writes: %s <- %s\n",ci_number, old_buf_device, old_buf_tuner);
        f = fopen(old_buf_device, "r+");
        fwrite(old_buf_tuner, strlen(old_buf_tuner), 1, f);
        fclose(f);
        }
    }

void push_new()
    {
    FILE *f;
    char buf_device[64];
    char buf_tuner[8];
    const char used_ci[] = "/proc/stb/tsmux/ci%d_input";
    snprintf(buf_device, sizeof(buf_device), used_ci, ci_number);

    /* getting tuner which the module uses currently */
    f = fopen(buf_device, "r");
    if (fread(buf_tuner, sizeof(buf_tuner), 1, f) < 1)
	{
	if (debug >9) lprintf("read current tuner failed\n");
	}

    fclose(f);
    buf_tuner[2]=0;
//  if (debug > 9) lprintf("CI%d PUSH: from %s read %s\n",ci_number, buf_device, buf_tuner);
    /* use last demux to write it back, so that we don't get sid in pat error */
    if ((strlen(old_buf_device) > 0) && (strncmp(buf_tuner,old_buf_tuner,2)!=0))
 	{
	if (debug > 9) lprintf("CI%d NEW tuner writes: %s <- %s\n",ci_number, buf_device, old_buf_tuner);
        f = fopen(buf_device, "r+");
        fwrite(old_buf_tuner, strlen(old_buf_tuner), 1, f);
        fclose(f);
        }
    /* getting source the demux uses currently */
    f = fopen(old_buf_device, "r");
    if (fread(buf_tuner, sizeof(buf_tuner), 1, f) < 1)
	{
	if (debug >9) lprintf("read current demux source failed\n");
	}
    fclose(f);
    buf_tuner[2]=0;
//  if (debug > 9) lprintf("CI%d PUSH: from %s read %s\n",ci_number, old_buf_device, buf_tuner);
    if ((strlen(old_buf_module) > 0) && (strncmp(buf_tuner,old_buf_module,2)!=0))
 	{
	if (debug > 9) lprintf("CI%d NEW demux writes: %s <- %s\n",ci_number, old_buf_device, old_buf_module);
        f = fopen(old_buf_device, "r+");
        fwrite(old_buf_module, strlen(old_buf_module), 1, f);
        fclose(f);
        }
    }

int check_standby()
{
	int standby=0;
   	FILE *stb;
	char line[256];
	const char *avs_input="/proc/stb/avs/0/input";
	/* check for standby via avs input */
	stb = fopen(avs_input, "r");
 	if (!fgets(line, sizeof(line), stb))
		{
   		if (debug > 0) lprintf("standby error: %s\n",strerror(errno)); 
		}
	fclose(stb);
	if (strncmp(line,"aux",3) == 0) 
	   {
           standby=1;
	   }
	if (debug > 6) lprintf("CI%d standby check: %d\n",ci_number, standby);
	return standby;
}

int check_timer(char *checkref, int verify)
{
	int i;
	int margin_before=0;
	int margin_after=0;
	int repeated=0;
   	FILE *timer;
	int ask_to_zap=1;
	FILE *settings;
	char line[256];
        current=0;
	justplay=0;
	if (debug > 9) lprintf("CI%d timer check current serviceref: %s check serviceref: %s\n",ci_number, currentref, checkref);

	/* nothing to check */
	if (strlen(checkref) == 0) return 0;

	char *timer_file="/etc/enigma2/timers.xml";
	timer = fopen(timer_file, "r");
	if (!timer)
	   { /* no timers to check as there is no timers.xml */
	   if (debug > 9) lprintf("CI%d NO TIMER\n", ci_number);
	   /* therefore we instantly reply no timer */
   	   return 0;
           }

     	settings = fopen("/etc/enigma2/settings", "rb");
	if (settings)
	   {
 	   while ( fgets ( line, sizeof(line), settings ) != NULL ) /* read a line */
		{
		/* timers.xml includes timestamps already 
           	   with before and after margin */
       		if (strncmp(line,"config.recording.margin_before=",31) == 0)
		   {
                   margin_before=60*atol(line+31);
		   if (debug > 9) lprintf(">>>> margin before %d sec\n",margin_before);
		   }
       		if (strncmp(line,"config.recording.margin_after=",30) == 0)
		   {
                   margin_after=60*atol(line+30);
		   if (debug > 9) lprintf(">>>> margin after %d sec\n",margin_after);
		   }
       		if (strncmp(line,"config.recording.asktozap=false",31) == 0)
		   {
                   ask_to_zap=0;
//		   if (debug > 9) lprintf(">>>> recording ask to zap %d\n",ask_to_zap);
		   }
	        }
	   }
        fclose(settings);

	if (!ask_to_zap)
	      { /* recordings should NOT have priority */
	      fclose(timer);
	      if (debug > 1) lprintf("CI%d RECORDING has NO priority\n", ci_number);
	      /* therefore we always reply no timer */
   	      return 0;
              }

	const char s[2] = "=";
	const char k[2] = "\"";
	char *token;
	char *recordingref="             ";
        char *same;
	int begin=0;
        int end=0;
        int delta=0;
        int days=0;
        int weeks=0;
	time_t result;
	int now;
   	result = time(NULL);
	now=(int)result;
	/* show only if clock is unset */
        if ((now<100000) && (debug > 9)) lprintf(">>>> NOW %d sec\n",now);

	/* first 2 lines are only xml header */
	if (!fgets(line, sizeof(line), timer)) 
		{
   		if (debug > 0) lprintf("timer error: %s\n",strerror(errno)); 
		}
	if (!fgets(line, sizeof(line), timer)) 
		{
   		if (debug > 0) lprintf("timer error: %s\n",strerror(errno)); 
		}
	while (fgets(line, sizeof(line), timer)) 
		{
//    		printf("!!%s!!\n", line); 
   		/* get the first token */
   		token = strtok(line, s);
		/* walk through tokens */
                i=0;
		begin=0;	
		end=0;	
		repeated=0;	
   		while( token != NULL ) 
      			{
//     			printf( "!%s!\n", token);
	      		if (i==1) 
                           {
			   /* 30 sec security margin */
			   begin=atol(token+1)-30;
                           if (debug > 9) lprintf(">>>> recording begin: %d\n", begin);
                           }
	      		if (i==2) 
			   {
			   /* 30 sec security margin */
			   end=atol(token+1)+30;
                           if (debug > 9) lprintf(">>>> recording end: %d\n", end);
			   }
	      		if (i==3) 
			   {
  			   recordingref=token+1;                                
                           token = strtok(recordingref, k);                     
                           recordingref=token;               
                           if (debug > 9) lprintf(">>>> recording serviceref: %s\n", recordingref);
			   }
	      		if (i==4) 
			   {
			   repeated=atol(token+1);
                           if (debug > 9) lprintf(">>>> repeated: %d\n", repeated);
			   }
	      		if (i==11) 
			   {
			   justplay=atol(token+1);
                           if (debug > 9) lprintf(">>>> justplay: %d\n", justplay);
			   }
      			token = strtok(NULL, s);
		
      			i++;
      			}
	           /* same transponder has same tsid and onid, but different sid */
		   if (strlen(serviceref) > 4)
                      {
		      same=strstr(serviceref+4,":");
//		      if (debug > 9) lprintf(">>>>>> SERV !%s! SAME !%s!\n",serviceref, same);
	              if (strstr(recordingref,same))
		         { /* second request is on same transponder */
		         current=1;
		         if (debug > 9) lprintf(">>>>>> same: %d\n",current);
		         }
		      }
//	        if (debug > 10) lprintf(">>>>>> now %d end %d\n",now, end);
		/* is this really needed for repeating timers ? */
		if ((end < now)  && (repeated > 0))
		   {
		   delta=now-end;
		   days=delta/86400;
		   weeks=days/7;
		   if (debug > 10) lprintf(">>>>>> days %d weeks %d\n",days,weeks);
		   if ((days > 0) && (repeated==127)) /* daily */
                      {
		      begin=begin+days*86400;
		      end=end+days*86400;
		      }
		   if ((weeks > 0) && (repeated==1)) /* weekly */
                      {
		      begin=begin+weeks*86400*7;
		      end=end+weeks*86400*7;
		      }

		   if (debug > 10) lprintf(">>>>>> next repeated: now %d begin %d end %d\n", now, begin, end);
		      
                   }

		/* if checkref  is a recording running NOW
                   then we reply that timer */
		if ((now > begin) && (now < end) && strstr(recordingref,checkref))
		   {
		   fclose(timer);
		   if (debug > 1) lprintf("CI%d RECORDING %s\n",ci_number, checkref);
	   	   /* if new serviceref we reset CI */
		   if (!verify)
			{
		   	push_old();
			}
   	   	   return 1;
		   }
    		}
	fclose(timer);
        /* no timer  */
	if (debug > 9) lprintf("CI%d NO RECORDING %s\n",ci_number, checkref);
	return 0;
}

int check_streaming(char *checkref, int verify)
{
	int ask_to_zap=1;
	FILE *settings;
	char line[256];
     	settings = fopen("/etc/enigma2/settings", "rb");
	if (settings)
	   {
 	   while ( fgets ( line, sizeof(line), settings ) != NULL ) /* read a line */
		{
       		if (strncmp(line,"config.streaming.asktozap=false",31) == 0)
		   {
                   ask_to_zap=0;
//		   if (debug > 9) lprintf(">>>> streaming ask to zap %d\n",ask_to_zap);
		   }
	        }
	   }
        fclose(settings);

	if (!ask_to_zap)
	      { /* streamings should NOT have priority */
	      if (debug > 1) lprintf("CI%d STREAMING has NO priority\n", ci_number);
	      /* therefore we always reply no stream */
   	      return 0;
              }

       DIR* dir = NULL;
       struct dirent *dirzeiger;
       char streamfile[256];
       sprintf(streamfile,"stream.%s",checkref);
       if ((dir = opendir("/tmp")) != NULL)
          {
          while ((dirzeiger = readdir(dir)) != NULL)
             {
             if (strcmp((*dirzeiger).d_name,streamfile)==0)
                {
		if (debug > 1) lprintf("CI%d STREAMING %s\n",ci_number, checkref);
	   	/* if new serviceref we reset CI */
		if (!verify)
			{
		   	push_old();
			}
		return 1;
                }
             }
          }
        closedir(dir);

	if (debug > 9) lprintf("CI%d NO STREAMING %s\n",ci_number, checkref);
	return 0;
}

int check_multicrypt()
	{
	/* default is auto which we use for same transponder */
	int can_descramble_multiple=AUTO;
	FILE *settings;
	char line[256];
	char cfg_yes[64];
	char cfg_no[64];
	char cfg_auto[64];
	sprintf(cfg_no,"config.ci.%d.canDescrambleMultipleServices=no",ci_number);
	sprintf(cfg_yes,"config.ci.%d.canDescrambleMultipleServices=yes",ci_number);
	sprintf(cfg_auto,"config.ci.%d.canDescrambleMultipleServices=auto",ci_number);
//	if (debug > 9) lprintf("CI setting: %s %s %s\n", cfg_no, cfg_yes, cfg_auto);
	settings = fopen("/etc/enigma2/settings", "rb");
	if (settings) {
 	   while ( fgets ( line, sizeof(line), settings ) != NULL ) /* read a line */
		{
                if (strncmp(line,cfg_no,44) == 0) { /* allow only 1 channel */
			can_descramble_multiple=NO;
            		}
                if (strncmp(line,cfg_yes,45) == 0) { /* simply allow 2 channels */
			can_descramble_multiple=YES;
            		}
                if (strncmp(line,cfg_auto,46) == 0) { /* we use auto for same transponder */
			can_descramble_multiple=AUTO;
            		}
	   	}
	   }
	fclose(settings);
	if (debug > 9) lprintf("CI%d can descramble multiple services %d\n",ci_number,can_descramble_multiple);
	return can_descramble_multiple;
	}

int check_ci_assignment(const uint8_t *data, unsigned int len)
{
	char channel[64];
	char *same;
	char *tmp;
	char sid[8];
	char tsid[8];
	char onid[8];
	char dvbns[10];
	int recording=0;
	int streaming=0;
	int header_ok=1;
        if (debug > 9) hexdump(data, len);

	/* check for ca_pmt header */
	if (*data++ != 0x9f) header_ok=0; /* tag 0 */
	if (*data++ != 0x80) header_ok=0; /* tag 1 */
	if (*data++ != 0x32) header_ok=0; /* tag 2 */
	if (!header_ok)
             {
	     if (debug > 3) lprintf(">>> no ca pmt header\n");
	     return 1;
	     }

	/* length field can be none or 0x81 or 0x82 */
	if (*data  > 0x80) {
		if (*data != 0x81) {
			data++;
		}
		data++;                                       
	}                                            
    
	data=data+2;                                           
	sprintf(sid,  "%02x", *data++);                        
	sprintf(sid+2,"%02x", *data++);
	if (debug > 9) lprintf("sid:    %s\n",sid);
	data=data+6;                                                
	sprintf(dvbns,   "%02x", *data++);                        
	sprintf(dvbns+2, "%02x", *data++);                        
	sprintf(dvbns+4, "%02x", *data++);                        
	sprintf(dvbns+6, "%02x", *data++);                        
	dvbns[9]=0;
	if (debug > 9) lprintf("dvbns:  %s\n",dvbns);
	sprintf(tsid,  "%02x", *data++);                        
	sprintf(tsid+2,"%02x", *data++); 
	if (debug > 9) lprintf("tsid:   %s\n",tsid);
	sprintf(onid,  "%02x", *data++);
	sprintf(onid+2,"%02x", *data++);
	if (debug > 9) lprintf("onid:   %s\n",onid);
	sprintf(channel,":%s:%s:%s:%s",sid,tsid,onid,dvbns);
	/* remove leading 0 */
	while (strstr(channel,":0") !=0) {
		tmp=replace_str(channel,":0",":");
		strcpy(channel,tmp);
	}
		
	/* remove blanks */
	char *np = serviceref, *op = channel;
	do 	{
	   	if (*op != ' ')
	       		*np++ = *op;
		} 
	while (*op++);

	/* make uppercase */
	int i=0;
    	while(serviceref[i]) 
		{
    		serviceref[i]=(toupper(serviceref[i]));
    		i++;
    		}

//	if (debug > 9) lprintf("serviceref %s\n",serviceref);
   	/* now get service reference and provider via lamedb */
    	get_service(sid,tsid,onid,dvbns);

	/* here comes the logic to decide if we handle this request */
    	if (debug > 9) lprintf("full serviceref: %s\n",fullserviceref);
    	if (debug > 5) lprintf("CI%d DESCRAMBLES: %d\n",ci_number, descrambles);

    	/* game over if NOT assigned */
    	if (!check_service())
		{
		return 1;
		}

    	/* game over if already working on a recording */
    	if ((descrambles > 1) && (check_timer(currentref, 1)))
		{
		push_new();
		if (debug > 2) lprintf("CI%d REJECTS second recording\n",ci_number);
		return 1;
		}

    	/* game over if already working on a stream */
    	if ((descrambles > 1) && (check_streaming(currentref, 1)))
		{
//		push_new();
		if (debug > 2) lprintf("CI%d REJECTS second streaming\n",ci_number);
		return 1;
		}

    	/* game over if third request */
	if (descrambles > 2)
		{	
		if (debug > 2) lprintf("CI%d REJECTS multicrypt\n",ci_number);
		return 3;
		}

    	/* game over if other module handles the requested channel already */
   	if (check_other(fullserviceref)) 
		{
		return 1;
		}

	if (descrambles > 1)
	   {
	   /* same transponder has same tsid and onid, but different sid */
	   same=strstr(serviceref+4,":");
	   if (debug > 2) lprintf("CI%d checks further ...\n",ci_number);

           switch (check_multicrypt()) 
        	{  
                case YES:
		   /* always accept 2 decryptions */
	   	   if (debug > 1) lprintf("CI%d ACCEPTS multicrypt\n",ci_number);
		   break;
                case AUTO:
//	   	   if (debug > 1) lprintf("CI%d MULTICRYPT serviceref: %s current: %s same: %s\n",ci_number, serviceref, currentref, same);
	           if (strstr(currentref,same))
		      { /* second request is on same transponder */
	   	      if (debug > 1) lprintf("CI%d ACCEPTS multicrypt on same transponder\n",ci_number);
	   	      }
		   else
		      {
	   	      if (debug > 1) lprintf("CI%d REJECTS multicrypt on different transponders\n",ci_number);
		      return 3;
	   	      }
		   break;
                default: /* NO multicyrpt */
	        	 /* this means last chance to allow decryption
	                    is that a recording or a stream could 
                            have priority */
	           if (!check_timer(fullserviceref, 0))
                      { 
	              if (!check_streaming(fullserviceref, 0)) 
                      	 { 
      	                 if (debug > 1) lprintf("CI%d REJECTS multiple decryption\n",ci_number);
                         return 3;
			 }
		      else
                         { 
		         /* prevent race condition */
		    //   sleep(ci_number);
		         streaming=1;
	                 }
                      } 
		   else
                      { 
		      /* prevent race condition */
//		      sleep(ci_number);
		      recording=1;
	              }
		   break;
        	}
       	   }

    	/* final check for somebody else doing the job */
//      if (debug > 9) lprintf("CI%d checks OTHER\n",ci_number);
   	if (check_other(fullserviceref)) 
		{
		return 1;
		}
	else
		{ /* looks like WE have do do the job */
		save_service_file(recording,streaming);
		return 0; 
		}
}

