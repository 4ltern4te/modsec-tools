# modsec-tools
Scripts to assist in ModSecurity admin


###modsec_replay
This tool reads a specific transaction from a ModSecurity audit log file and replays it against a desired server to aid in testing ModSecurity rules.

`./modsec_replay.py -i ec54a708 -f /var/log/httpd/modsec_audit.log -s http://server:port -t 'Host:example.com'`

###modsec_parse
This tool reads a specific transaction from a ModSecurity audit log file and creates exemptions for ModSecurity and Apache. Only use this against a log file that has known good traffic (i.e from a staging env after function testing has been completed).

`./modsec_parse.py -f /var/log/httpd/modsec_audit.log -u`


