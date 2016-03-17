#!/bin/sh

NBSH_NODE_HARDWARE=/tmp/cache/router_hardware_cache
NBSH_NODE_SDD=/tmp/cache/router_sdd_cache
NBSH_NODE_RADIO=/tmp/cache/router_radio_cache

usage()
{
	echo "nbsh_sync_cmd.sh sync_file"
}

nbsh_node_sync()
{
	cmd_file=`mktemp`
	echo -e "enable\nenable" > $cmd_file
	echo "configure terminal" >> $cmd_file
	cat $1 >> $cmd_file
	echo -e "end\nwrite memory\nexit\nexit" >> $cmd_file
	nbsh -x $cmd_file
	rm -rf $cmd_file
}

if [ $1 = "hardware" ]; then
	nbsh_node_sync $NBSH_NODE_HARDWARE
elif [ $1 = "sdd" ]; then
	nbsh_node_sync $NBSH_NODE_SDD
elif [ $1 = "radio" ]; then
	nbsh_node_sync $NBSH_NODE_RADIO
else
	usage
fi

exit 0