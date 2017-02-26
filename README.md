LOAD MODULE:    sudo ./load
UNLOAD MODULE:  sudo ./unload

The initial state is:

KMonitor Current Configuration:
-------------------------------
File Monitoring    - Disabled;
Network Monitoring - Disabled;
Mount Monitoring   - Disabled;

To Enable:
-------------------------------
echo MountMon 1 > /proc/KMonitor
echo FileMon  1 > /proc/KMonitor
echo NetMon   1 > /proc/KMonitor


Remmember to disable rsyslogd to avoid loop read + write with kern.log, syslog.


