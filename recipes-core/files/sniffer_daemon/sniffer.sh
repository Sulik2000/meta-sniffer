#!/bin/sh
### BEGIN INIT INFO
# Provides:          sniffer
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start my packet sniffer
### END INIT INFO

DAEMON=/usr/bin/sniffer
NAME=sniffer
DESC="Network Sniffer"

test -f $DAEMON || exit 0

set -e

case "$1" in
    start)
        echo -n "Starting $DESC: "
        start-stop-daemon -S -b -x "$DAEMON"
        echo "$NAME"
        ;;
    stop)
        echo -n "Stopping $DESC: "
        start-stop-daemon -K -x "$DAEMON"
        echo "$NAME"    
        ;;
    restart|force-reload)
        echo -n "Restarting $DESC: "
        start-stop-daemon -K -x "$DAEMON"
        sleep 1
        start-stop-daemon -S -b -x "$DAEMON"
        echo "$NAME"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|force-reload}" >&2
        exit 1
        ;;
esac

exit 0