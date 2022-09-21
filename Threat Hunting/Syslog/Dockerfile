FROM ubuntu

RUN apt update && apt install rsyslog -y
RUN echo '$ModLoad imudp\n\
$UDPServerRun 514 \n\
$template Auth_Log, "/var/log/remote/auth_log \n\
$template Access_Log, "/var/log/remote/access_log" \n\
$template Event_Log, "/var/log/remote/event_log \n\
local1.* ?Auth_Log \n\
local2.* ?Access_Log \n\
local3.* ?Event_Log' > /etc/rsyslog.conf

ENTRYPOINT [ "rsyslogd", "-n" ]