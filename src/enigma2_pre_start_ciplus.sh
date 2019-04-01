#!/bin/sh
#
/sbin/start-stop-daemon -S -b -n dreamciplus0 -x /usr/bin/dreamciplus -- /dev/ci0
/sbin/start-stop-daemon -S -b -n dreamciplus1 -x /usr/bin/dreamciplus -- /dev/ci1
#
# stopping of both daemons
#
#/sbin/start-stop-daemon -K -p /tmp/dreamciplus0.pid
#/sbin/start-stop-daemon -K -p /tmp/dreamciplus1.pid
#
# test status of both daemons
#
#/sbin/start-stop-daemon -K -t -p /tmp/dreamciplus0.pid
#/sbin/start-stop-daemon -K -t -p /tmp/dreamciplus1.pid
#
exit 0
