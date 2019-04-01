#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/termios.h>
#include <sys/ioctl.h>
#include <unistd.h>

void lprintf(char* message,...);
extern int debug;
extern int ci_number;

void parse(char *line, char **argv)
{
     while (*line != '\0') {       /* if not the end of line ....... */ 
          while (*line == ' ' || *line == '\t' || *line == '\n')
               *line++ = '\0';     /* replace white spaces with 0    */
          *argv++ = line;          /* save the argument position     */
          while (*line != '\0' && *line != ' ' && 
                 *line != '\t' && *line != '\n') 
               line++;             /* skip the argument until ...    */
     }
     *argv = '\0';                 /* mark the end of argument list  */
}

int nohup(char *line)
{
	int exit_status;
        char* argv[32];
        pid_t child_pid;
//	pid_t sid = 0;

	if (strlen(line) == 0) 
		{
	        if (debug > 9) lprintf("CI%d NOHUP no argument\n", ci_number);
		return 0;
		}
	else
		{
	        if (debug > 9) lprintf("CI%d NOHUP command %s\n", ci_number, line);
		}
	parse(line,argv);
        child_pid = fork();
        if(child_pid == 0) 
            {
	    if (debug > 9) lprintf("CI%d NOHUP child executes\n", ci_number);

	    int i;
	    for (i=getdtablesize()-1; i>=0; --i) close(i);

	    /* unmask the file mode */                           
	    umask(0);                                               
	    /* set new session */                                      
            setpgid(0,0);  /* set the process group */
/*
	    sid = setsid();                                         
            if(sid < 0)                                             
                {                                                       
	        if (debug > 9) lprintf("CI%d NOHUP no new sid\n", ci_number);
                return -1;
                }                                                       
*/
//	    chdir("/");                                             

	    int fd;
	    fd = open("/dev/tty", O_RDWR);
	    ioctl(fd, TIOCNOTTY, 0);
            close(fd);

            /* redirect stdin, stdout and stderr */                      
	    fd = open("/dev/null",O_RDWR, 0);
            if (fd != -1) 
		{   
  		dup2 (fd, STDIN_FILENO);
  		dup2 (fd, STDOUT_FILENO);
  		dup2 (fd, STDERR_FILENO);
  		if (fd > 2)
  			close (fd);
		}

            /* This is done by the child process. */
	    if (debug > 9) lprintf("CI%d NOHUP executes %s %s %s\n", ci_number, argv[0], argv[1], argv[2]);
	    execvp(argv[0], &argv[0]);
            /* If execvp returns, it must have failed. */
	    if (debug > 9) lprintf("CI%d NOHUP failed (%s)\n", ci_number, strerror(errno));
	    exit_status = (errno == ENOENT);
	    return(exit_status);
            }
        else 
            {
	    /* successfull return */
	    if (debug > 9) lprintf("CI%d NOHUP mother returns\n", ci_number);
	    usleep(1000);
            return 1;
            }
}
