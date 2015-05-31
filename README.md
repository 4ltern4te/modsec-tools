# modsec-tools
Scripts to assist in ModSecurity admin


###modsec_replay
This tool reads a specific transaction from a ModSecurity audit log file and replays it against a desired server to aid in testing ModSecurity rules.

`./modsec_replay.py -i ec54a708 -f /var/log/httpd/modsec_audit.log -s http://server:port -t 'Host:example.com'`


Polishing some others for public consumption. Stay tuned.
