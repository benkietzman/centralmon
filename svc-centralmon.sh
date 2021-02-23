#!/sbin/sh
#
# Central Monitor - centralmon daemon init script
#

LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/lib:/usr/local/ssl/lib:/usr/sfw/lib
export LD_LIBRARY_PATH

. /lib/svc/share/smf_include.sh
if [ -x /usr/local/sbin/centralmon ]; then
  /usr/local/sbin/centralmon --daemon
else
  echo "/usr/local/sbin/centralmon is missing or not executable."
  exit $SMF_EXIT_ERR_CONFIG
fi
exit $SMF_EXIT_OK
