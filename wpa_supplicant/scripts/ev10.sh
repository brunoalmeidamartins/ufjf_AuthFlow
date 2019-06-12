#!/bin/sh
#wpa_cli -atst.sh
IFNAME=$1
CMD=$2

if [ "$CMD" = "CONNECTED" ]; then
    libiec61850-1.2/uff/2con/ve_yona/./ve_yona.exe ev10 10.0.0.3
    echo $?
fi

if [ "$CMD" = "DISCONNECTED" ]; then
    echo "kill ve?"
fi
