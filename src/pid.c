/*
    pidfile.c - interact with pidfiles
    Copyright (c) 1995  Martin Schulze <Martin.Schulze@Linux.DE>

 * This file is part of rsyslog.
 *
 * Rsyslog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Rsyslog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Rsyslog.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

#include "misc.h"

extern int debug;
extern char ci_name_underscore[128];

/* read_pid
 *
 * Reads the specified pidfile and returns the read pid.
 * 0 is returned if either there's no pidfile, it's empty
 * or no pid can be read.
 */
int read_pid (char *pidfile)
{
  FILE *f;
  int pid;
  int ret;

  if (!(f=fopen(pidfile,"r")))
    return 0;
  ret=fscanf(f,"%d", &pid);
  if (!ret) 
       {      
       if (debug > 0) lprintf("pid error: %s\n",strerror(errno));
       }     
  fclose(f);
  return pid;
}

/* write_pid
 *
 * Writes the pid to the specified file. If that fails 0 is
 * returned, otherwise the pid.
 */
int write_pid (char *pidfile, int pid)
{
  FILE *f;
  int fd;

  if ( ((fd = open(pidfile, O_RDWR|O_CREAT, 0644)) == -1)
       || ((f = fdopen(fd, "r+")) == NULL) ) {
      if (debug > 0) lprintf("can't open or create %s\n", pidfile);
      return 0;
  }

  if (pid==0)
	{
  	pid = getpid();
	}
  if (!fprintf(f,"%d\n", pid)) {
      if (debug > 0) lprintf("can't write pid\n");
      close(fd);
      return 0;
  }
  fflush(f);
  close(fd);

  return pid;
}

/* remove_pid
 *
 * Remove the the specified file. The result from unlink(2)
 * is returned
 */
int remove_pid (char *pidfile)
{
  FILE *f;
  if (!(f=fopen(pidfile,"r")))
    return 0;
  fclose(f);
  return unlink (pidfile);
}
  
