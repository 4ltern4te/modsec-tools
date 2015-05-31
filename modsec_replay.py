#!/usr/bin/env python

# Written by 4ltern4te to aid with ModSecurity admin
# Not fully tested, my code is evidently not great ;), USE AT OWN RISK.

# TODO:
# Test the remaining HTTP request headers
# Write better logging / debug output
# Clean up code, comment, share

from optparse import OptionParser
import urllib
import time
import sys
import os
import itertools
import re
import requests


'''
This function processes a ModSecurity audit log file in to a dictionary of dictionai.
The first dictionary contains the ModSecurity audit log transaction ID as the dictionary key
and values are the A-Z section of the ModSecurity audit log entry which act as keys to the
second layer of dictionaries that contains the values of of the A-Z sections for a given log file
entry ID.

For example in a ascii visual:
dict[modsec_log_entry_id]->dict[modsec_log_entry_id_section]->value[contents_under_section]
4849145d->"--4849145d-A--"->"[01/Jan/1970:12:56:12 +1100] VFwmvH8AAAEAABuxd54AAACH 172.16.0.7 54320 172.16.1.1 80"
4849145d->"--4849145d-B--"->"GET /BLAHBLAH/ETC/ETC"
'''
def process_modsec_file(filename):

    try:
        modsec_fd = open(filename, "r")
    except IOError as e:
        print 'Cant open %s because: %s' % (filename, e)
        sys.exit(1)

    content = modsec_fd.read()

    d_modsec = {}

    # Start with regex --3d482f30-A-- end with regex --3d482f30-Z-- for example
    entries = re.findall("(--[0-9a-f]{8}-A--)(.*?)(--[0-9a-f]{8}-Z--)", content, re.DOTALL)

    for entry in entries:

        # for each entry turn the list in to a string
        entry = ''.join(entry)

        # Get each trans header so we can create a dictionary out of it
        trans_list = re.findall('--[0-9a-f]{8}-[A-Z]--.*?', entry, re.DOTALL)

        # Get the uniq tranaction ID modsecurity generates
        tid = re.search("--([0-9a-f]{8})-A--", str(trans_list))
        trans_id = tid.group(1)

        # For each transaction break it down in to the A-Z sub catagories modsec does
        id_dic = {}
        for trans in trans_list:

            # The actual regex below (--[0-9a-f]{8}-A--)(.*?)(--[0-9a-f]{8}-[A-Z]--)
            search = "(" + trans + ")" + "(.*?)(--[0-9a-f]{8}-[A-Z]--)"

            id = re.findall(search, entry, re.DOTALL)
            if len(id) > 0:
                id_dic[id[0][0]] = id[0][1]

                # Add this dictionary to the bigger one
                d_modsec[trans_id] = id_dic


    modsec_fd.close()
    return d_modsec


# Look for modsec_audit.log file entry by transaction ID
def grep_for(modsec_contents, grep_regex):
    output = ""
    modsec_section = "--" + grep_regex + "-[A-Z]--"
    for tid, tvalues in modsec_contents.items():
        for key, value in tvalues.items():
            match = re.search(modsec_section, key)
            if match:
                return modsec_contents[tid]

# Pull out specific data from a modsec_audit.log file entry by transaction ID
def grep_for_section(modsec_contents, grep_regex, section):
    output = ""
    modsec_section = "--" + grep_regex + "-" + section + "--"
    for tid, tvalues in modsec_contents.items():
        match = re.search(modsec_section, tid)
        if match:
            return tvalues

# URL Decode for the modsec_audit.log entry so that we can replay it as the
# webserver saw it and not encoded
def modsec_url_decode(log_entry):

    # For each value in the dictionary run urldecode over it and then put it back
    for key, value in log_entry.items():
        log_entry[key] = urllib.unquote(value.encode('ascii'))


# Manipulate the selected modsec_audit.log transaction data so that we can
# replay it to a destination of our choosing
def modsec_to_request(modsec_log_entry):

    new_headers = {}

    modsec_url_decode(modsec_log_entry)

    output_b = grep_for_section(modsec_log_entry, options.modsec_id, "B")

    # Pull what we need to out of the modsec audit file to build our request.
    find = re.search("((CONNECT|DELETE|GET|HEAD|OPTIONS|POST|PUT|TRACE)\s(.*?))\sHTTP\/1\.(1|0)\n(.*)",output_b,re.DOTALL)
    req = find.group(1)
    method = find.group(2)
    uri = find.group(3)
    headers = find.group(5)
    headers = headers.strip()
    headers = re.sub(":\s+?", ":", headers)
    headers = headers.split("\n")

    # Split the HTTP headers up in to a dictionary based on the first ":" we see
    # to avoid splits on http":"//host":"8080/ etc
    [new_headers.update(dict([i.split(":", 1)])) for i in headers]

    post_body = ""
    post_body_dict = {}


    # If we have a PUT or POST then we need to grab the request body data to
    # push on to our slected server
    if method.upper() == "POST":
        # Pull out POST data
        output_c = grep_for_section(modsec_log_entry, options.modsec_id, "C")
        post_body = re.search("(.*)",output_c,re.DOTALL)

	    # split by "&" and then split by "=" for request library expected input format
        post_body = str(post_body.group(0))
        post_body = post_body.split('&')
        [post_body_dict.update(dict([i.split("=")])) for i in post_body]

    # PUT is different to POST because PUT body is just the data you want to push/put to the webserver
    if method.upper() == "PUT":
        output_c = grep_for_section(modsec_log_entry, options.modsec_id, "C")
        post_body = re.search("(.*)",output_c,re.DOTALL)


    return (method, uri, new_headers, post_body_dict)


if __name__ == '__main__':

    usage = sys.argv[0] + """ -i modsec-audit-log-id -f modsec_audit.log -s http://172.16.1.100:80 -t 'Host:example.com,User-Agent:iPhone,X-YourHeader:SecretValue'"""

    parser = OptionParser(usage=usage)
    parser.add_option("-f", "--file", dest="filename",
                  help="ModSecurity Audit log file to read from")
    parser.add_option("-i", "--id", dest="modsec_id",
                  help="ModSecurity Audit log file entry to use. i.e: ec54a708 from --ec54a708-A--")
    parser.add_option("-s", "--host", dest="host",
                  help="IP address to send the request to")
    parser.add_option("-t", "--headers", dest="header_options",
                  help="User supplied header values to override audit entry header values")
    parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")

    (options, args) = parser.parse_args()


    if options.filename is None:
        print "[!] Required ModSecurity audit log file argument --file is missing."
        sys.exit(1)
    if options.modsec_id is None:
        print "[!] Required ModSecurity audit log transaction id argument --id is missing."
        sys.exit(1)
    if options.host is None:
        print "[!] Required Host/IP address argument is missing."
        sys.exit(1)


    headers = {}
    if options.header_options:
        try:
            # Remove white spaces from the headers command line argument so we
            # dont replay something like "Host:    example.com"
            options.header_options = options.header_options.replace(' ', '')

            # English: Take first command line argument split the string up by a "," and
            # then for each element of the split create a dictionary object by
            # splitting the HTTP header values by a ":" and then
            # append it to a dictionary variable to parse to a HTTP request call
            # later in the code. If the format does not match on the cli thow exception.
            [headers.update(dict([i.split(":", 1)])) for i in options.header_options.split(",")]
            #print headers

        except ValueError as e:
            print "\nError: %s.\n\tCheck that your header options are of the format 'Host:example.com,User-Agent:iPhone'\n" % e
            sys.exit(1)


    # Process and read the modsec_audit.log file return the matched entry if it exists
    output = {}
    try:
        output = grep_for(process_modsec_file(options.filename), options.modsec_id)
        if output == None:
            raise ValueError()
    except ValueError:
        print "\nError: Issue looking for ModSecurity Audit Log file entry. Does it exist?\n"
        sys.exit(1)

    # Parse the output variable for all the required header values to make a
    # request and then munge our header variable above to overwrite file values
    # with the cli ones.
    (method, uri, new_headers, post_data) = modsec_to_request(output)


    # TODO: Grab Host/IP from the Host header if its not passed on the cmd line.
    url = options.host + uri
    new_headers.update(headers)

    # try to make a request to the destination server of choice. If it does not
    # work out then catch the exception and quit
    try:
        if method.upper() == "GET":
            r = requests.get(url, headers=new_headers)
            print r.status_code, r.headers

        if method.upper() == "HEAD":
            r = requests.head(url, headers=new_headers)
            print r.status_code, r.headers

        # Untested
        if method.upper() == "OPTIONS":
            r = requests.head(url, headers=new_headers)
            print r.status_code, r.headers

        if method.upper() == "POST":
            r = requests.post(url, headers=new_headers, data=post_data)
            print r.status_code, r.headers

        # Untested
        if method.upper() == "PUT":
            r = requests.put(url, headers=new_headers, data=post_data)
            print r.status_code, r.headers

        # Untested
        if method.upper() == "DELETE":
            r = requests.put(url, headers=new_headers, data=post_data)
            print r.status_code, r.headers


    except requests.exceptions.ConnectionError as e:
        print "[!] Connection Error: %s. Exiting" % e
        sys.exit(1)

    except requests.exceptions.HTTPError as e:
       print "[!] HTTP Error: %s. Exiting" % e
       sys.exit(1)

    except requests.exceptions.Timeout as e:
       print "[!] Read or Connect Timeout: %s. Exiting" % e
       sys.exit(1)

    except requests.exceptions.TooManyRedirects as e:
       print "[!] Redirect Limit Reached: %s. Exiting" % e
       sys.exit(1)
    
    finally:
        sys.exit(0)
