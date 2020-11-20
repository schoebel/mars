# Regular cron jobs for MARS
#

PATH=/sbin:/bin:/usr/sbin:/usr/bin

# MARS transaction logfile rotation + deletion every x minutes

*/10 * * * *	root	if [ -L /mars/uuid ] ; then marsadm cron ; fi > /dev/null 2>&1
*/5,15,25,35,45,55 * * * *	root	if [ -L /mars/uuid ] ; then marsadm log-delete-all all ; fi > /dev/null 2>&1

