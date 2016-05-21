#!/usr/bin/env python

# TODO:
# QA the output / results. I have noticed potential edge cases already
# Complete Debugging output
# Based a fair bit of login on: https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--(Updated)-Exception-Handling/
#

import sys
import os
import re
from optparse import OptionParser

import pdb

#
# Grep for and spit out matching entries
# I am aware of how ugly this is :| improvments welcomed
#
def grep_for(modsec_contents, grep_regex):
    for tid, tvalues in modsec_contents.items():
        for key, value in tvalues.items():
            match = re.search(grep_regex, value)
            if match:
                print '-' * 30
                for k in sorted(tvalues.keys()):
                    print '%s%s' % (k, tvalues[k])
                print '-' * 30

#
# Make our data one long delimited grepable string
# This is mainly for teh nix pipes 
#
def make_grep(modsec_contents):
    
    # Need to strip out alllll the \n - do this with re.sub()
    for tid, tvalues in modsec_contents.items():
        for key in sorted(tvalues.keys()):
            print re.sub(r"\n+?", " ", str(key.strip())), re.sub(r"\n+?", " ", str(tvalues[key].strip()))

#
# Remove Modsecurity rules by id per variable for selected URLs
#
def update_url_target_by_id(modsec_contents, custom_rule_id):
   
    config_output = []
    debug_output = {}


    # Loop over the modsec_audit.log file contents. We know at this point we
    # have transactions and thus we know that the variables tid and tvalues will
    # populate without issue
    for tid, tvalues in modsec_contents.items():
        id_f = "--" + str(tid) + "-F--"
        id_b = "--" + str(tid) + "-B--"
        id_h = "--" + str(tid) + "-H--"

        # Grab the REQUEST_FILENAME from the log transaction
        m1 = re.search('(/.*?)(\?|\;|\s)', str(tvalues[id_b]))
        if m1:
            url_short = m1.group(1)

        try:
            if DEBUG:
                d_m = re.findall("Message\:.*?\n", str(tvalues[id_h]))
                #d_m = re.findall("Message\:.*?\[id\s\"\d+?\"\].*?\n", str(tvalues[id_h]))
                if d_m:
                    d = ', '.join(map(str, d_m))
                    debug_output[str(tid)] = d

            
            # Munge a SecRule together with the url, rule id and the Modsecurity
            # variable name that the rule blocked on
            # the md5 is a shitty replace canary at this point. REPLACE IT for
            # the love of gawddddd
            #message_match = re.findall("Message\:(.*?)\sat\s(.*?)\.\s\[.*?\[id\s\"(\d+?)\"\].*?\n", str(tvalues[id_h]))
            message_match = re.findall("Message\:(.*?)\sat\s((ARGS|ARGS_COMBINED_SIZE|ARGS_GET|ARGS_GET_NAMES|ARGS_NAMES|ARGS_POST|ARGS_POST_NAMES|AUTH_TYPE|DURATION|ENV|FILES|FILES_COMBINED_SIZE|FILES_NAMES|FULL_REQUEST|FULL_REQUEST_LENGTH|FILES_SIZES|FILES_TMPNAMES|FILES_TMP_CONTENT|GEO|HIGHEST_SEVERITY|INBOUND_DATA_ERROR|MATCHED_VAR|MATCHED_VARS|MATCHED_VAR_NAME|MATCHED_VARS_NAMES|MODSEC_BUILD|MULTIPART_CRLF_LF_LINES|MULTIPART_FILENAME|MULTIPART_NAME|MULTIPART_STRICT_ERROR|MULTIPART_UNMATCHED_BOUNDARY|OUTBOUND_DATA_ERROR|PATH_INFO|PERF_COMBINED|PERF_GC|PERF_LOGGING|PERF_PHASE1|PERF_PHASE2|PERF_PHASE3|PERF_PHASE4|PERF_PHASE5|PERF_RULES|PERF_SREAD|PERF_SWRITE|QUERY_STRING|REMOTE_ADDR|REMOTE_HOST|REMOTE_PORT|REMOTE_USER|REQBODY_ERROR|REQBODY_ERROR_MSG|REQBODY_PROCESSOR|REQUEST_BASENAME|REQUEST_BODY|REQUEST_BODY_LENGTH|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_LINE|REQUEST_METHOD|REQUEST_PROTOCOL|REQUEST_URI|REQUEST_URI_RAW|RESPONSE_BODY|RESPONSE_CONTENT_LENGTH|RESPONSE_CONTENT_TYPE|RESPONSE_HEADERS|RESPONSE_HEADERS_NAMES|RESPONSE_PROTOCOL|RESPONSE_STATUS|RULE|SCRIPT_BASENAME|SCRIPT_FILENAME|SCRIPT_GID|SCRIPT_GROUPNAME|SCRIPT_MODE|SCRIPT_UID|SCRIPT_USERNAME|SDBM_DELETE_ERROR|SERVER_ADDR|SERVER_NAME|SERVER_PORT|SESSION|SESSIONID|STREAM_INPUT_BODY|STREAM_OUTPUT_BODY|TIME|TIME_DAY|TIME_EPOCH|TIME_HOUR|TIME_MIN|TIME_MON|TIME_SEC|TIME_WDAY|TIME_YEAR|TX|UNIQUE_ID|URLENCODED_ERROR|USERID|USERAGENT_IP|WEBAPPID|WEBSERVER_ERROR_LOG|XML).*?)\.\s\[.*?\[id\s\"(\d+?)\"\].*?\n", str(tvalues[id_h]))
            if message_match:
                for match in message_match:
                    
                    out = 'SecRule REQUEST_FILENAME "@beginsWith ' \
                    + url_short + '" ' + '"phase:1,t:none,pass,id:' + \
                    "fc1baf8a4b263d6d3d3e4e267648febb" + \
                    ',nolog,ctl:ruleRemoveTargetById=' + match[3] + ';' + match[1] + '"'
                    
                    config_output.append(out)
            
        except KeyError as e:
            print >>sys.stderr, "Exception caught but continuing: update_target_by_id(): %s", e
            continue
    

    # End of the processing loop, beginning of the output loops
    
    if DEBUG:
        for key in sorted(debug_output):
            print "Modsecurity Transaction ID %s: %s" % (key, debug_output[key])

    # Output the SecRule with auto generating custom rule IDs for 'id:'
    print "\n\n\n"
    if len(config_output) > 0:
        config_output = sorted(set(config_output))
        for i in config_output:
            s = re.sub('fc1baf8a4b263d6d3d3e4e267648febb', str(custom_rule_id), str(i))
            custom_rule_id = custom_rule_id + 1
            print s
    
    print "\n"
    return True

#
# Parse a modsec_audit file and yeild SecRuleUpdateTargetById rules for all requests that resulted in a 403 HTTP return code 
#
def update_target_by_id(modsec_contents):
   
    config_output = []
    debug_output = {}


    # Loop over the modsec_audit.log file contents. We know at this point we
    # have transactions and thus we know that the variables tid and tvalues will
    # populate without issue
    for tid, tvalues in modsec_contents.items():
        id_f = "--" + str(tid) + "-F--"
        id_b = "--" + str(tid) + "-B--"
        id_h = "--" + str(tid) + "-H--"

        try:
            if DEBUG:
                d_m = re.findall("Message\:.*?\n", str(tvalues[id_h]))
                #d_m = re.findall("Message\:.*?\[id\s\"\d+?\"\].*?\n", str(tvalues[id_h]))
                if d_m:
                    d = ', '.join(map(str, d_m))
                    debug_output[str(tid)] = d

            #Message: Warning. Invalid URL Encoding: Not enough characters at the
            #end of input at REQUEST_URI.
            #message_match = re.findall("Message\:(.*?)\sat\s(.*?)\.\s\[.*?\[id\s\"(\d+?)\"\].*?\n", str(tvalues[id_h]))
            message_match = re.findall("Message\:(.*?)\sat\s((ARGS|ARGS_COMBINED_SIZE|ARGS_GET|ARGS_GET_NAMES|ARGS_NAMES|ARGS_POST|ARGS_POST_NAMES|AUTH_TYPE|DURATION|ENV|FILES|FILES_COMBINED_SIZE|FILES_NAMES|FULL_REQUEST|FULL_REQUEST_LENGTH|FILES_SIZES|FILES_TMPNAMES|FILES_TMP_CONTENT|GEO|HIGHEST_SEVERITY|INBOUND_DATA_ERROR|MATCHED_VAR|MATCHED_VARS|MATCHED_VAR_NAME|MATCHED_VARS_NAMES|MODSEC_BUILD|MULTIPART_CRLF_LF_LINES|MULTIPART_FILENAME|MULTIPART_NAME|MULTIPART_STRICT_ERROR|MULTIPART_UNMATCHED_BOUNDARY|OUTBOUND_DATA_ERROR|PATH_INFO|PERF_COMBINED|PERF_GC|PERF_LOGGING|PERF_PHASE1|PERF_PHASE2|PERF_PHASE3|PERF_PHASE4|PERF_PHASE5|PERF_RULES|PERF_SREAD|PERF_SWRITE|QUERY_STRING|REMOTE_ADDR|REMOTE_HOST|REMOTE_PORT|REMOTE_USER|REQBODY_ERROR|REQBODY_ERROR_MSG|REQBODY_PROCESSOR|REQUEST_BASENAME|REQUEST_BODY|REQUEST_BODY_LENGTH|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_LINE|REQUEST_METHOD|REQUEST_PROTOCOL|REQUEST_URI|REQUEST_URI_RAW|RESPONSE_BODY|RESPONSE_CONTENT_LENGTH|RESPONSE_CONTENT_TYPE|RESPONSE_HEADERS|RESPONSE_HEADERS_NAMES|RESPONSE_PROTOCOL|RESPONSE_STATUS|RULE|SCRIPT_BASENAME|SCRIPT_FILENAME|SCRIPT_GID|SCRIPT_GROUPNAME|SCRIPT_MODE|SCRIPT_UID|SCRIPT_USERNAME|SDBM_DELETE_ERROR|SERVER_ADDR|SERVER_NAME|SERVER_PORT|SESSION|SESSIONID|STREAM_INPUT_BODY|STREAM_OUTPUT_BODY|TIME|TIME_DAY|TIME_EPOCH|TIME_HOUR|TIME_MIN|TIME_MON|TIME_SEC|TIME_WDAY|TIME_YEAR|TX|UNIQUE_ID|URLENCODED_ERROR|USERID|USERAGENT_IP|WEBAPPID|WEBSERVER_ERROR_LOG|XML).*?)\.\s\[.*?\[id\s\"(\d+?)\"\].*?\n", str(tvalues[id_h]))
            if message_match:
                for match in message_match:
                    out = "SecRuleUpdateTargetById " + match[3] + " !" + match[1]
                    config_output.append(out)

        except KeyError as e:
            print >>sys.stderr, "Exception caught but continuing: update_target_by_id(): %s", e
            continue
    
    # End of the processing loop, beginning of the output loops
    
    # Output the 
    if DEBUG:
        for key in sorted(debug_output):
            print "Modsecurity Transaction ID %s: %s" % (key, debug_output[key])

    print "\n\n\n"
    if len(config_output) > 0:
        config_output = sorted(set(config_output))
        for i in config_output:
            if "anomaly_score" not in i: print i
    
    print "\n"
    for i in config_output:
        if "anomaly_score" in i: 
            print i
    print "\n" 

#
# Provide the URL the RemoveSecID rule and the reason for the 403. This only
# works for known good traffic.
#
def remove_by_id(modsec_contents):
    
    config_output = {}
    for tid, tvalues in modsec_contents.items():
        id_f = "--" + str(tid) + "-F--"
        id_b = "--" + str(tid) + "-B--"
        id_h = "--" + str(tid) + "-H--"
            
        try:
            m1 = re.search(".*?\[id \"(.*?)\"\].*?", tvalues[id_h])
        except Exception as e: 
            #print >>sys.stderr, "Exception caught but continuing: remove_by_id(): %s", e
            continue
        
        try:
            m2 = re.search('(/.*?)(\?|\;|\s)', tvalues[id_b])
        except Exception as e: 
            #print >>sys.stderr, "Exception caught but continuing: remove_by_id(): %s", e
            continue

        config_output[m2.group(1)] = m1.group(1)
            
    # print config_output
    for cid, cvalue in config_output.items():
        print "\n<LocationMatch \"" + cid + "\">"
        print "\tSecRuleRemoveById " + cvalue
        print "</LocationMatch>" + "\n"
        
#
# Function takes the filename for the modsec_audit.log
# opens it reads the contents in an places each transaction in a dictionary of a dictionary
#
def process_modsec_file(filename):
    
    try:
        modsec_fd = open(filename, "r")
    except all as e:
        print 'Cant open %s because: %s' % (modsec_file, e)
        sys.exit(1)
    
    content = modsec_fd.read()
    
    d_modsec = {}
    
    # Start with regex --3d482f30-A-- end with regex --3d482f30-Z--
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

# Global variables. I know, i know.
DEBUG = 0

if __name__ == '__main__':

    # Take command line options
    usage = """sys.argv[0] -f <modsec_audit.log> -s <string to look for in entries> -d <output with delimeter>
               I do not reccomend doing all these options at once or you are going to have a whole lot of output"""
    parser = OptionParser(usage=usage)
    parser.add_option("-f", "--file", dest="filename",
           help="modsec_audit.log to read from")
    parser.add_option("-s", "--string", dest="grep_string",
           help="Regex to grep with")
    parser.add_option("-d", "--delimit", dest="delimiter",
           help="Output all log entries with ")
    parser.add_option("-i", "--update-by-id", dest="update_id", action="store_true",
           help="Output SecRuleUpdateTargetById rules for the file")
    parser.add_option("-u", "--update-by-url-id", dest="url_update_id", action="store_true",
           help="Output SecRuleUpdateTargetById rules for the file")
    parser.add_option("-z", "--custom-rule-id-start", dest="custom_start_id", default=int(999911),
            help="Output SecRuleUpdateTargetById rules for the file")
    parser.add_option("-v", "--debug", dest="debug", action="store_true",
           help="Output SecRuleUpdateTargetById rules for the file")
    parser.add_option("-r", "--remove-by-id", dest="rm_id", action="store_true",
           help="Output the url and the SecRuleRemoveById followed by the block message")

    (options, args) = parser.parse_args()

    if not options.filename:
        print '[!] Need to specify -f option. Use -h --help for usage'
        sys.exit(1)

    d_mod = process_modsec_file(options.filename)
    
    if options.debug:
        DEBUG = options.debug

    if options.rm_id:
        remove_by_id(d_mod)
    
    if options.grep_string:
        grep_for(d_mod, options.grep_string)
    
    if options.delimiter:
        make_grep(d_mod)

    if options.update_id:
        update_target_by_id(d_mod)
    
    if options.url_update_id:
        update_url_target_by_id(d_mod, int(options.custom_start_id))
