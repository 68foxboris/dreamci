#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/utsname.h>
#include <getopt.h>
#include <errno.h>
#include <stdarg.h>

#include "misc.h"

/* define some colors */
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m" 
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

/* global stuff */
extern int v1;
extern int v2;
extern int  classic;
extern char ci_name_underscore[128];
extern int  debug;
extern int  logging;
extern int  foreground;
extern int  autopin;
extern int  extract_ci_cert;
extern int  connect_mmi;
extern char logfile[256];

extern char *dream_ci_bin;
extern char *dream_ci_bin_mipsel;
extern char *dream_ci_bin_armhf;
extern char *dream_ci_so;
extern char *dream_ci_so_mipsel;
extern char *dream_ci_so_armhf;

extern char *dream_ci_legacy1;
extern char *dream_ci_legacy2;
extern char *dream_ci_legacy3;
extern char *dream_ci_legacy4;
extern char *dream_ci_legacy5;

extern struct utsname u;
extern char *dreambox;  
extern int  quiet; 
extern int fifo_pipe;
extern int standalone;
extern int max_ci;

extern int dreamciplus(int ci_command, int slot);

extern void version(FILE *output);

extern pid_t GetPIDbyName_Wrapper(const char* cchrptr_ProcessName, ... );

#define GetPIDbyName(ProcessName,...) GetPIDbyName_Wrapper(ProcessName, ##__VA_ARGS__, (int) 15)

void usage()
  {
  char *plus=" [--plus] ";
  if (dreambox == NULL) plus="          ";
  fprintf(stderr, "Usage:   dreamciplus <device>  [--start/stop/restart]\n            %s[--auto] [--mmi] [--extract] [--quiet]\n                [--foreground] [--log file]  [--debug level]\n\nService: dreamciplus <start/stop/restart/status/erase> [slot]\n\n",plus);
  exit(0);
  }

int main(int argc, char *argv[])
{
        FILE *settings;
        FILE *pid_file;
	FILE *service_file;
    	struct stat buf;
	char *service_start="[Unit]\nDescription=Dreambox CI Plus\nRequires=dev-dvb-adapter0-ca0.device dev-dvb-adapter0-demux0.device dev-sci0.device\nBefore=enigma2-environment.service enigma2.service\nAfter=dev-dvb-adapter0-ca0.device\nAfter=dev-dvb-adapter0-demux0.device\nAfter=dev-sci0.device\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/dreamciplus start\nExecReload=/usr/bin/dreamciplus restart\nExecStop=/usr/bin/dreamciplus stop\nRemainAfterExit=yes\nRestart=no\nNonBlocking=true\nKillMode=process\nTimeoutStopSec=1\n\n[Install]\nWantedBy=multi-user.target\n";
	char *exclusive="   start/stop/restart are exclusive\n   don't use other options at the same time\n\n";
        char procfilename[32];
	int start;
	int plus;
	char command[256];
	char ci_dev[256];
	char line[256];
	char cfg[256];
	int ret=0;
	int pid;
        char pidfilename[32];
	int slot=0;
	standalone=1; /* only if main is used as binary enable standalone */
	enum { NONE, START, STOP, RESTART } ci_command=NONE;

        if (uname(&u) != 0)
           {
           if (debug > 9) lprintf("KERNEL unknown\n");
	   u.release[0]=0;
	   u.nodename[0]=0;
	   }

	/* count number of CI slots */
	max_ci=count_files("/dev", "ci");

	char vu[3];
	vu[0]=118;
	vu[1]=117;
	vu[2]=0;
  	if (strncmp(u.nodename,vu,2)==0) max_ci=1;  /* no comment */

	/* support installation arguments */
	if (argc > 1)
	   {
	   if (!strcmp(argv[1],"configure"))
		{
		fprintf(stdout, "\n");
		fprintf(stdout, "Configuring dreamciplus (%d.%d) ...\n",v1,v2);
		fprintf(stdout, "\n");
	     	service_file = fopen("/lib/systemd/system/dreamciplus.service", "w+");
		if (service_file)
			{
			fwrite(service_start, strlen(service_start), 1, service_file);
			fclose(service_file);
			/* remove old stuff */
			remove(dream_ci_legacy1);
			remove(dream_ci_legacy2);
			remove(dream_ci_legacy3);
			remove(dream_ci_legacy4);
			}
		else
			{
			ret=symlink("/usr/bin/dreamciplus","/etc/rcS.d/S66dreamciplus");
                        if (ret)
                                {
                                if (debug > 0) lprintf("symlink error ...\n");
                                }

			ret=symlink("/usr/bin/dreamciplus","/etc/rc6.d/K66dreamciplus");
                        if (ret)
                                {
                                if (debug > 0) lprintf("symlink error ...\n");
                                }
			ret=symlink("/usr/bin/dreamciplus","/etc/rc1.d/K66dreamciplus");
                        if (ret)
                                {
                                if (debug > 0) lprintf("symlink error ...\n");
                                }
			ret=symlink("/usr/bin/dreamciplus","/etc/rc0.d/K66dreamciplus");
                        if (ret)
                                {
                                if (debug > 0) lprintf("symlink error ...\n");
                                }
			/* remove old stuff */
			remove(dream_ci_legacy5);
			}
		ret=symlink("/lib/systemd/system/dreamciplus.service","/etc/systemd/system/multi-user.target.wants/dreamciplus.service");
                if (ret)
                        {
                        if (debug > 0) lprintf("symlink error ...\n");
                        }

/*
		unlink(dream_ci_so);
		unlink(dream_ci_so_armhf);
		unlink(dream_ci_so_mipsel);
*/

    		lstat (dream_ci_bin, &buf);
		/* if binary is not linked we are done */
    		if (S_ISREG(buf.st_mode)) 
			exit(0);

		if (!strcmp(u.machine,"mips"))
			{
			ret=symlink(dream_ci_bin_mipsel,dream_ci_bin);
                	if (ret)
                       		{
                        	if (debug > 0) lprintf("symlink error ...\n");
                        	}
			/* replace unneeded armhf with empty file */
			remove(dream_ci_bin_armhf);
			open (dream_ci_bin_armhf, O_RDWR|O_CREAT,0);
			}
		else
			{
			ret=symlink(dream_ci_bin_armhf,dream_ci_bin);
                	if (ret)
                       		{
                        	if (debug > 0) lprintf("symlink error ...\n");
                        	}
			/* replace unneeded mipsel with empty file */
			remove(dream_ci_bin_mipsel);
			open (dream_ci_bin_mipsel, O_RDWR|O_CREAT,0);
			}
		exit(0);
		}
	   if (!strcmp(argv[1],"remove"))
		{
		fprintf(stdout, "\n");
		fprintf(stdout, "Removing dreamciplus (%d.%d) ...\n",v1,v2);
		fprintf(stdout, "\n");
	     	service_file = fopen("/lib/systemd/system/dreamciplus.service", "w+");
		if (service_file)
			{
			fclose(service_file);
		        remove("/lib/systemd/system/dreamciplus.service");
		        remove("/etc/systemd/system/multi-user.target.wants/dreamciplus.service");
			remove(dream_ci_legacy1);
			remove(dream_ci_legacy2);
			remove(dream_ci_legacy3);
			remove(dream_ci_legacy4);
			}
		else
			{
			remove("/etc/rcS.d/S66dreamciplus");
			remove("/etc/rc6.d/K66dreamciplus");
			remove("/etc/rc1.d/K66dreamciplus");
			remove("/etc/rc0.d/K66dreamciplus");
			remove(dream_ci_legacy5);
			}			 
                /* remove classic binaries */
                unlink(dream_ci_bin);
                settings = fopen(dream_ci_bin_mipsel, "rb");
                if (settings)
                        {
                        fclose(settings);
                        remove(dream_ci_bin_mipsel);
                        }
                settings = fopen(dream_ci_bin_armhf, "rb");
                if (settings)
                        {
                        fclose(settings);
                        remove(dream_ci_bin_armhf);
                        }

		exit(0);
		}
	   if (!strcmp(argv[1],"upgrade"))
		{
		/* simply do nothing */
		exit(0);
		}
	   }

	mkdir("/var/run/ca", 0777);
 	dreambox=strstr(u.release,"dm");                                                  
	version(stdout);
	if (argc > 1)
	   {
	   if (!strcmp(argv[1],"start"))
		{
		if (argc > 2)
			{
			slot=atol(argv[2]);
			if (slot < max_ci)
				{
				sprintf(command,"%s /dev/ci%d --start", dream_ci_bin, slot);
				fprintf(stdout, KGRN"[DCP] STARTING CI%d\n"KNRM, slot);
				nohup(command);
				}
			else
				{
				fprintf(stdout, KGRN"[DCP] MISSING CI%d\n"KNRM, slot);
				}
			fprintf(stdout, "\n");
			exit(0);
			}
		int started=0;
		for (slot=0; slot<max_ci; slot++)
			{
			start=1;
	     	   	settings = fopen("/etc/enigma2/settings", "rb");
		   	if (settings)
		      		{
				sprintf(cfg,"config.ci.%d.start=false",slot);
		      		/* read a line */ 
 		      		while ( fgets ( line, sizeof(line), settings ) != NULL ) 
					{
       		         		if (strncmp(line,cfg,23) == 0) 
		   				{
						start=0;
		   				}
		   			}
       	      			fclose(settings);
				}
			plus=0;
           		settings = fopen("/etc/enigma2/settings", "rb");
           		if (settings)
              			{
              			sprintf(cfg,"config.ci.%d.plus=true",slot);
              			/* read a line */
              			while ( fgets ( line, sizeof(line), settings ) != NULL )
                			{
                			if (strncmp(line,cfg,21) == 0)
                        			{
                        			plus=1;
                        			}
                			}
              			fclose(settings);
              			}

			sprintf(command,"%s /dev/ci%d --start", dream_ci_bin, slot);
			if (start)
				{
		                sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
                 		pid=0;
                 		pid_file = fopen(pidfilename, "r");
                 		if (pid_file)
                         		{
                         		fclose(pid_file);
                         		pid=read_pid(pidfilename);
                         		}
                		 if (pid > 0)
                         		{
			                sprintf(procfilename,"/proc/%d",pid);
	                 		pid_file = fopen(procfilename, "r");
	                 		if (pid_file)
                         			{
	                         		fclose(pid_file);
						}
					else
                         			{
						remove(pidfilename);
						pid=0;
						}
					}
                		if (pid > 0)
                       			{
                         		fprintf(stdout, KGRN"[DCP] RUNNING CI%d\n"KNRM, slot);
                         		}
                 		else
					{
					fprintf(stdout, KGRN"[DCP] STARTING CI%d\n"KNRM, slot);
					nohup(command);
					}
				started++;
	       	      		}
			else
				{
				fprintf(stdout, KGRN"[DCP] START DISABLED CI%d"KNRM, slot);
       	      			}
			fprintf(stdout, "\n");
       	      		}
		/* give daemons a chance to grab CI devices 
		   unfortunately this slows down boot
                   because we have to let enigma2 wait ... */
        	int max_pid=0;                           
		int timeout=0;
		while ((max_pid < started) && (timeout < 5))
			{
			max_pid=count_files("/var/run/ca","dreamciplus");
			fprintf(stdout, KGRN"[DCP] STARTED  #%d/%d\n"KNRM, max_pid, started);
			sleep(1);
			timeout++;
			}
		sleep(2); 
		fprintf(stdout, KGRN"\n[DCP] STARTING FINISHED\n\n"KNRM);
		exit(0);
		}

	   if ((!strcmp(argv[1],"stop")) || (!strcmp(argv[1],"kill")))
		{
		if (argc > 2)
			{
			slot=atol(argv[2]);
    			sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
     	   		pid_file = fopen(pidfilename, "r");
	   		if (pid_file)
	      			{
				fclose(pid_file);
				pid=read_pid(pidfilename);
				if (pid > 0)
					{
					fprintf(stdout, KGRN"[DCP] STOPPING CI%d %d\n"KNRM,slot, pid);
					kill(pid, SIGABRT);
					fprintf(stdout, "\n");
					}
	     	   		remove(pidfilename);
				}
			exit(0);
			}
		for (slot=0; slot<max_ci; slot++)
			{
    			sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
     	   		pid_file = fopen(pidfilename, "r");
	   		if (pid_file)
	      			{
				fclose(pid_file);
				pid=read_pid(pidfilename);
				if (pid > 0)
					{
					fprintf(stdout, KGRN"[DCP] STOPPING CI%d %d\n"KNRM,slot, pid);
					kill(pid, SIGABRT);
					fprintf(stdout, "\n");
					}
	     	   		remove(pidfilename);
				}
       	      		}
//		fprintf(stdout, "\n");
		exit(0);
		}

	   if (!strcmp(argv[1],"restart") || !strcmp(argv[1],"erase") )
		{
		if (argc > 2 || max_ci == 1)
			{
			if (max_ci == 1)
				{
				slot=0;
				}
			else
				{
				slot=atol(argv[2]);
				}

	   		if (!strcmp(argv[1],"erase"))
				{
				reset_auth(slot);
				}

    			sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
     	   		pid_file = fopen(pidfilename, "r");
	   		if (pid_file)
	      			{
				fclose(pid_file);
				pid=read_pid(pidfilename);
				if (pid > 0)
					{
					fprintf(stdout, KGRN"[DCP] STOPPING CI%d %d\n"KNRM,slot, pid);
					kill(pid, SIGABRT);
//					fprintf(stdout, "\n");
					sleep(2);
					}
	     	   		remove(pidfilename);
				}
			if (slot < max_ci)
				{
				sprintf(command,"%s /dev/ci%d --start", dream_ci_bin, slot);
				fprintf(stdout, KGRN"[DCP] STARTING CI%d\n"KNRM, slot);
				nohup(command);
				}
			else
				{
				fprintf(stdout, KGRN"[DCP] MISSING CI%d\n"KNRM, slot);
				}
			fprintf(stdout, "\n");
			exit(0);
			}
	   	if (!strcmp(argv[1],"restart"))
		{
		for (slot=0; slot<max_ci; slot++)
			{
    			sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
     	   		pid_file = fopen(pidfilename, "r");
	   		if (pid_file)
	      			{
				fclose(pid_file);
				pid=read_pid(pidfilename);
				if (pid > 0)
					{
					fprintf(stdout, KGRN"[DCP] STOPPING CI%d %d\n"KNRM,slot, pid);
					kill(pid, SIGABRT);
					sleep(2);
					fprintf(stdout, "\n");
					}
	     	   		remove(pidfilename);
				}
			start=1;
	     	   	settings = fopen("/etc/enigma2/settings", "rb");
		   	if (settings)
		      		{
				sprintf(cfg,"config.ci.%d.start=false",slot);
		      		/* read a line */ 
 		      		while ( fgets ( line, sizeof(line), settings ) != NULL ) 
					{
       		         		if (strncmp(line,cfg,23) == 0) 
		   				{
						start=0;
		   				}
		   			}
       	      			fclose(settings);
				}
			plus=0;
           		settings = fopen("/etc/enigma2/settings", "rb");
           		if (settings)
              			{
              			sprintf(cfg,"config.ci.%d.plus=true",slot);
              			/* read a line */
              			while ( fgets ( line, sizeof(line), settings ) != NULL )
                			{
                			if (strncmp(line,cfg,21) == 0)
                        			{
                        			plus=1;
                        			}
                			}
              			fclose(settings);
              			}
			sprintf(command,"%s /dev/ci%d --start", dream_ci_bin, slot);
			if (start)
				{
				fprintf(stdout, KGRN"[DCP] STARTING CI%d\n"KNRM, slot);
				nohup(command);
	       	      		}
			else
				{
				fprintf(stdout, KGRN"[DCP] START DISABLED CI%d\n"KNRM, slot);
       	      			}
			fprintf(stdout, "\n");
       	      		}
		exit(0);
		}
	   }

	   char piddy[8];
	   char procy[32];
	   int  pidint;
	   if (!strcmp(argv[1],"status"))
		{
		for (slot=0; slot<max_ci; slot++)
			{
    			sprintf(pidfilename,"/var/run/ca/dreamciplus%d.pid",slot);
     	   		pid_file = fopen(pidfilename, "r");
	   		if (pid_file)
	      			{
				pidint=0;
				pidint=fread(piddy,sizeof(piddy),1,pid_file);
				pidint=atol(piddy);
				fclose(pid_file);
				sprintf(procy,"/proc/%d",pidint);
     	   			pid_file = fopen(procy, "r");
	   			if (pid_file)
	      				{
					fclose(pid_file);
					fprintf(stdout, KGRN"[DCP] CI%d RUNNING %d "KNRM,slot,pidint);
					}
				else
	      				{
					remove(pidfilename);
    					/* remove the service file */
					remove_service_file();
    					/* remove the caid file */
					remove_caid_file();
    					/* remove the CI name file */
    					remove_name_file(ci_name_underscore);
					fprintf(stdout, KGRN"[DCP] CI%d STOPPED %d "KNRM,slot,pidint);
					}
				}
			else
	      			{
				fprintf(stdout, KGRN"[DCP] CI%d STOPPED "KNRM,slot);
				}
			start=1;
	     	   	settings = fopen("/etc/enigma2/settings", "rb");
		   	if (settings)
		      		{
				sprintf(cfg,"config.ci.%d.start=false",slot);
		      		/* read a line */ 
 		      		while ( fgets ( line, sizeof(line), settings ) != NULL ) 
					{
       		         		if (strncmp(line,cfg,23) == 0) 
		   				{
						start=0;
		   				}
		   			}
       	      			fclose(settings);
				}
			if (start)
				{
				fprintf(stdout, KGRN"& ENABLED"KNRM);
	       	      		}
			else
				{
				fprintf(stdout, KGRN"& DISABLED"KNRM);
	       	    	 	}
			plus=0;
	     	   	settings = fopen("/etc/enigma2/settings", "rb");
		   	if (settings)
		      		{
				sprintf(cfg,"config.ci.%d.plus=true",slot);
		      		/* read a line */ 
 		      		while ( fgets ( line, sizeof(line), settings ) != NULL ) 
					{
       		         		if (strncmp(line,cfg,21) == 0) 
		   				{
						plus=1;
		   				}
		   			}
       	      			fclose(settings);
				}
			if (plus)
				{
				fprintf(stdout, KGRN" & PLUS\n"KNRM);
	       	      		}
			else
				{
				fprintf(stdout, "\n");
	       	      		}
	       	    	}
		fprintf(stdout, "\n");
		exit(0);
	       	}
	   /* ignore non ci devices but allow device numbers 0|1 */
	   strcpy(ci_dev,argv[1]);

	   if (strlen(ci_dev) == 1)
		{
		slot=atol(ci_dev);
	   	if((slot < 0) || (slot > (max_ci-1))) 
			{
			usage();
			return 1;
			}
		sprintf(ci_dev,"/dev/ci%d",slot);
		}
	   else
		{
	   	slot=atol(ci_dev+7);
	   	if((strncmp(ci_dev,"/dev/ci",7)) || (slot < 0) || (slot > 1)) 
			{
			usage();
			return 1;
			}
		}
	   }
	else
	   {
	   usage();
	   return 1;
	   }

        sprintf(logfile,"/tmp/dreamciplus%d.log",slot);

	/* proper command line handling */    
	int c;
        while(1)
           {
           static struct option long_options[] =
            {
              {"autopin",    no_argument,       0, 'a'},
              {"classic",    no_argument,       0, 'c'},
              {"help",       no_argument,       0, 'h'},
              {"mmi",        no_argument,       0, 'm'},
              {"start",      no_argument,       0, 's'},
              {"restart",    no_argument,       0, 'r'},
              {"stop",       no_argument,       0, 'k'},
              {"extract",    no_argument,       0, 'e'},
              {"foreground", no_argument,       0, 'f'},
              {"plus",       no_argument,       0, 'p'},
              {"quiet",      no_argument,       0, 'q'},
              {"debug",      required_argument, 0, 'd'},
              {"log",        required_argument, 0, 'l'},
              {0, 0, 0, 0}
            };

	int option_index = 0;

        c = getopt_long (argc, argv, "hcmpqsrkefd:l:",
                       long_options, &option_index);
        if (c == -1)
           break;

        switch(c)
          {
          case 'l':
	    logging=1;
	    if (optarg != NULL)
		{
            	strcpy(logfile,optarg);
		}
            break;
          case 'a':
	    autopin=1;
            break;
          case 'q':
	    quiet=0;
            break;
          case 'c':
	    classic=1;
            break;
          case 'm':
	    connect_mmi=0;
            break;
          case 'f':
	    foreground=1;
            break;
          case 'p':
	    fifo_pipe=0;
            break;
          case 'e':
	    extract_ci_cert=1;
            break;
          case 'd':
	    if (optarg != NULL)
		{
	        debug=atoi(optarg);
		}
	    if (debug < 0) debug = 0;
	    if (debug > 10) debug = 10;
            break;
          case 's':
		if (ci_command == NONE)
			{
			ci_command=START;
			if (debug > 0) fprintf(stdout, KGRN"[DCP] STARTING CI%d\n"KNRM, slot);
			}
		else
			{
			fprintf(stdout, KGRN"%s"KNRM, exclusive);
			exit(0);
			}
            break;
          case 'k':
		if (ci_command == NONE)
			{
			ci_command=STOP;
			if (debug > 0) fprintf(stdout, KGRN"[DCP] STOPPING CI%d\n\n"KNRM, slot);
			}
		else
			{
			fprintf(stdout, KGRN"%s"KNRM, exclusive);
			exit(0);
			}
            break;
          case 'r':
		if (ci_command == NONE)
			{
			ci_command=RESTART;
			if (debug > 0) fprintf(stdout, KGRN"[DCP] RESTARTING CI%d\n"KNRM, slot);
			}
		else
			{
			fprintf(stdout, KGRN"%s"KNRM, exclusive);
			exit(0);
			}
            break;
          case 'h':
	    usage();
	    return 1;
            break;
          case 'v':
	    return 1;
            break;
          case '?':
            if (isprint (optopt))
               fprintf (stderr, "    wrong usage of option -%c\n    try -h for help\n\n", optopt);
            else
               fprintf (stderr,
               "    unknown option character \\x%x\n    try -h for help\n\n",
               optopt);
	    return 1;
            break;
          default:
	    usage();
	    return 1;
            }

      }

	/* let us have a nice process name */ 
	int len;
	int j,k;
	len=strlen(argv[0]);

#ifdef NAME
	if (len>10)
		{
		strncpy(argv[0],"dreamciplus",11);
		if (slot==0)
			{
			argv[0][11]=48;
			}
		else
			{
			argv[0][11]=49;
			}
		for(j=12; j<len; j++)
			{
			argv[0][j]=0;
			}
		}
#else
	if (len>5)
		{
		strncpy(argv[0],"[ci/ ]",6);
		if (slot==0)
			{
			argv[0][4]=48;
			}
		else
			{
			argv[0][4]=49;
			}
		for(j=6; j<len; j++)
			{
			argv[0][j]=0;
			}
		}
#endif

	/* clear remaining arguments */
	for (j=1;j<argc;j++)
		{
		len=strlen(argv[j]);
		for(k=0; k<len; k++)
			{
			argv[j][k]=0;
			}
		}

      prctl(PR_SET_NAME, argv[0]);

      ret=dreamciplus(ci_command, slot);
      return ret;
      
}
