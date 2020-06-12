#!/usr/bin/env python
PROGRAM_NAME = "cg-flow-summary.py"
PROGRAM_DESCRIPTION = """
CloudGenix WAN Capacity Graph
---------------------------------------
This program displays summary statistics for flow data given a Site Name, Time Period, Application, and Source IP
If either Application or Source IP are not given, we will implicitly assume all APP's or Source IP's and not 
filter flows based on it.

USAGE:
optional arguments:
  -h, --help            show this help message and exit
  --token "MYTOKEN", -t "MYTOKEN"
                        specify an authtoken to use for CloudGenix
                        authentication
  --authtokenfile "MYTOKENFILE.TXT", -f "MYTOKENFILE.TXT"
                        a file containing the authtoken
  --site-name SiteName, -s SiteName
                        The site to run the site health check for
  --period period, -p period
                        The period of time (in hours) for the resulting graph.
                        Default 1 hour
  --src-ip-prefix srcipprefix, -i srcipprefix
                        The source IP to filter on. Default 0.0.0.0/0
  --app app, -a app     The Application to filter on. Default all
  --days days, -d days  How many days back to look for flow summary data.
                        Default 0 (today)

EXAMPLES:
    Show todays flows for the past 1 hour for all source-ip's and apps at chicago
        cg-flow-summary.py --authtokenfile ~/token-karl-demopod1.txt --site-name chicago

    Show 8-hours of flow summary for New York from yesterday. Authentication will be handled interactively.
        cg-flow-summary.py -s york -d 1 -p 8

    Show 24-hours of flow summary data for New York Branch from 7 days ago for a 24 hour period for the 
    app Dropbox and the source HOST IP of 192.168.20.102.
        cg-flow-summary.py --authtokenfile ~/token-karl-demopod1.txt -s york -d 7 -p 24 -a dropbox -i 192.168.20.102/32

NOTES:
    The time Period parameter must take a numeric form with optional period designation E.G.:
        -p 1    1 Hour (Hours are implicit)
        -p 30s  30 Seconds
        -p 15m  15 Minutes
        -p 1.5  1 Hour and a half
    if a number is passed, we will implicitly assume you meant hours

    There is a hard limit of 1,000 flows which may be returned currently. If the result includes more than 1,000 flows
    a warning will be displayed. We will still return summary data for the first 1,000 flows. It is recommended you 
    decrease your filter scope to keep the results lower.

    Site and Application name matching is done via fuzzy matching and the program will select the closests result based on 
    your input.

    Source IP address filtering input should take the CIDR format  of x.x.x.x/y where x.x.x.x is an IPv4 address and y is a 
    CIDR prefix

"""

####Library Imports
from cloudgenix import API, jd
import os
import sys
import argparse
import ipaddress
from fuzzywuzzy import fuzz
from datetime import datetime, timedelta


def parse_arguments():
    CLIARGS = {}
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=PROGRAM_DESCRIPTION
            )
    parser.add_argument('--token', '-t', metavar='"MYTOKEN"', type=str, 
                    help='specify an authtoken to use for CloudGenix authentication')
    parser.add_argument('--authtokenfile', '-f', metavar='"MYTOKENFILE.TXT"', type=str, 
                    help='a file containing the authtoken')
    parser.add_argument('--site-name', '-s', metavar='SiteName', type=str, 
                    help='The site to run the site health check for', required=True)
    parser.add_argument('--period', '-p', metavar='period', type=str, 
                    help='The period of time (in hours) for the resulting graph. Default 1 hour', default=1)
    parser.add_argument('--src-ip-prefix', '-i', metavar='srcipprefix', type=str, 
                    help='The source IP to filter on. Default 0.0.0.0/0', default="0.0.0.0/0")
    parser.add_argument('--app', '-a', metavar='app', type=str, 
                    help='The Application to filter on. Default all', default="all")
    parser.add_argument('--days', '-d', metavar='days', type=int, 
                    help='How many days back to look for flow summary data. Default 0 (today)', default=0)
    args = parser.parse_args()
    CLIARGS.update(vars(args))
    try:
        ipprefix = ipaddress.ip_network(CLIARGS['src_ip_prefix'], strict=False)
    except:
        print("    ","ERROR: Invalid IP Prefix entered. Must take the form of 1.1.1.0/24 or 2.2.2.2/32")
        sys.exit()

    CLIARGS['ipprefix'] = ipprefix
    return CLIARGS

def authenticate(CLIARGS):
    print("AUTHENTICATING...")
    user_email = None
    user_password = None
    
    sdk = API()    
    ##First attempt to use an AuthTOKEN if defined
    if CLIARGS['token']:                    #Check if AuthToken is in the CLI ARG
        CLOUDGENIX_AUTH_TOKEN = CLIARGS['token']
        print("    ","Authenticating using Auth-Token in from CLI ARGS")
    elif CLIARGS['authtokenfile']:          #Next: Check if an AuthToken file is used
        tokenfile = open(CLIARGS['authtokenfile'])
        CLOUDGENIX_AUTH_TOKEN = tokenfile.read().strip()
        print("    ","Authenticating using Auth-token from file",CLIARGS['authtokenfile'])
    elif "X_AUTH_TOKEN" in os.environ:              #Next: Check if an AuthToken is defined in the OS as X_AUTH_TOKEN
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
        print("    ","Authenticating using environment variable X_AUTH_TOKEN")
    elif "AUTH_TOKEN" in os.environ:                #Next: Check if an AuthToken is defined in the OS as AUTH_TOKEN
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
        print("    ","Authenticating using environment variable AUTH_TOKEN")
    else:                                           #Next: If we are not using an AUTH TOKEN, set it to NULL        
        CLOUDGENIX_AUTH_TOKEN = None
        print("    ","Authenticating using interactive login")
    ##ATTEMPT AUTHENTICATION
    if CLOUDGENIX_AUTH_TOKEN:
        sdk.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if sdk.tenant_id is None:
            print("    ","ERROR: AUTH_TOKEN login failure, please check token.")
            sys.exit()
    else:
        while sdk.tenant_id is None:
            sdk.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not sdk.tenant_id:
                user_email = None
                user_password = None            
    print("    ","SUCCESS: Authentication Complete")
    return sdk

def match_site(sdk, search_site):
    if not sdk.tenant_id:
        sys.exit("Error SDK not authenticated")
    search_ratio = 0
    
    resp = sdk.get.sites()
    if resp.cgx_status:
        site_list = resp.cgx_content.get("items", None)    #site_list contains an list of all returned sites
        for site in site_list:                            #Loop through each site in the site_list
            check_ratio = fuzz.ratio(search_site.lower(),site['name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                site_dict = site
    else:
        logout()
        print("ERROR: API Call failure when enumerating SITES in tenant! Exiting!")
        sys.exit((jd(resp)))
    print("Found SITE ")
    print("     Site Name: " , site_dict['name'])
    print("       Site ID: " , site_dict['id'])
    print("   Description: " , site_dict["description"])
 
    return site_dict


def match_app(sdk, search_app):
    if not sdk.tenant_id:
        sys.exit("Error SDK not authenticated")
    search_ratio = 0
    
    resp = sdk.get.appdefs()
    if resp.cgx_status:
        app_list = resp.cgx_content.get("items", None)  
        for app in app_list:                            
            check_ratio = fuzz.ratio(search_app.lower(),app['display_name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                app_dict = app
    else:
        logout()
        print("ERROR: API Call failure when enumerating SITES in tenant! Exiting!")
        sys.exit((jd(resp)))
    print("Found APP ")
    print("     APP Name: " , app_dict['display_name'])
    print("       APP ID: " , app_dict['id'])
    print("  Description: " , app_dict["description"])
 
    return app_dict

def logout(sdk):
    print("Logging out")
    sdk.get.logout()

##########MAIN FUNCTION#############
def go(sdk, global_vars):
    ####CODE GOES BELOW HERE#########
    days_ago = global_vars['days'] ###How many days ago to look
    try:
        if ("m" in global_vars['period']):
            statistics_period = float(global_vars['period'].replace("m","")) / 60
            print("Time Period:",global_vars['period'].replace("m",""),"Minutes")
        elif ("d" in global_vars['period']):
            statistics_period = float(global_vars['period'].replace("d","")) * 24
            print("Time Period:",global_vars['period'].replace("d",""),"Days")
        elif ("s" in global_vars['period']):
            statistics_period = (float(global_vars['period'].replace("s","")) / 60) / 60
            print("Time Period:",global_vars['period'].replace("s",""),"Seconds")
        elif  ("h" in global_vars['period']):
            statistics_period = float(global_vars['period'].replace("h",""))
            print("Time Period:",statistics_period,"Hours")
        else:
            statistics_period = float(global_vars['period'])
            print("Time Period:",statistics_period,"Hours")
    except:
        print("ERROR: Invalid Period entered. Must take a numeric form with optional period designation E.G.: ")
        print("    ","-p 1    1 Hour (Hours are implicit)")
        print("    ","-p 30s  30 Seconds")
        print("    ","-p 15m  15 Minutes")
        print("    ","-p 1.5  1 Hour and a half")
        return False



    hours_ago = days_ago * 24  
    today = datetime.today()
    #today = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)
    start_time = str((today - timedelta(hours=hours_ago)).isoformat()) 
    end_time = str((today - timedelta(hours=(hours_ago-statistics_period))).isoformat())

    print("Time period filter from",start_time,"to",end_time)
    search_site = global_vars['site_name']

    global_vars['site_obj'] = match_site(sdk, search_site)
    site_name = global_vars['site_obj']['name']
    site_id  = global_vars['site_obj']['id']
    search_app = global_vars['app']

    json_flow_request = {"start_time":  start_time + 'Z' ,"end_time": end_time + 'Z',"filter":{"site":[site_id]},"debug_level":"all"}
    if (search_app != "all"):
        global_vars['app_obj'] = match_app(sdk, search_app)
        app_name = global_vars['app_obj']['display_name']
        app_id = global_vars['app_obj']['id']
        #json_flow_request = '{"start_time":"' + start_time + 'Z","end_time":"' + end_time + 'Z","filter":{"site":["' + site_id + '"],"app":["' + app_id + '"]},"debug_level":"all"}'
        json_flow_request['filter']['app'] = [app_id]

    if (str(CLIARGS['ipprefix']) != "0.0.0.0/0"):
        str_ip_src = str(CLIARGS['ipprefix'])
        json_flow_request['filter']['flow'] = {"source_ip": [str_ip_src]}
        print("Filtering based on Source IP/Subnet",str_ip_src)

    ##EXAMPLE Filter W/O APP
    #json_flow_request = '{"start_time":"2020-06-11T22:48:26.440Z","end_time":"2020-06-11T23:48:26.440Z","filter":{"site":["15003251159470085"]},"debug_level":"all"}'
    ##Example WITH APP
    #{"start_time":"2020-06-11T22:50:18.554Z","end_time":"2020-06-11T23:50:18.554Z","filter":{"site":["15003251159470085"],"app":["14992955969580091"]},"debug_level":"all"}
    
    flow_result = sdk.post.flows_monitor(json_flow_request)
    if (flow_result.cgx_status):
        flow_list = flow_result.cgx_content.get("flows").get("items")
    else:
        print("ERROR", "API Response error")
        return False   
    print("Flows Retrieved Successully, Processing Flows")

    
    
    flow_metrics_list = [   'init_success',
                            'bytes_c2s', 'bytes_s2c', 
                            'reset_c2s', 'reset_s2c', 
                            'retransmit_bytes_c2s', 'retransmit_bytes_s2c', 
                            'retransmit_pkts_c2s', 'retransmit_pkts_s2c', 
                            'ooo_pkts_c2s', 'ooo_pkts_s2c', 
                            ]
    flow_counts = {}
    for metric in flow_metrics_list:
        flow_counts[metric] = 0
    flow_counts['priority_class-0'] = 0
    flow_counts['priority_class-1'] = 0
    flow_counts['priority_class-2'] = 0
    flow_counts['priority_class-3'] = 0
    flow_counts['priority_class-4'] = 0

    
    print("Flows Found: ", len(flow_list))
    if len(flow_list) >= 1000:
        print("WARNING:","More than 1,000 flows returned. DATA WILL BE INCOMPLETE")
    if len(flow_list) == 0:
        print(" No FLOWS Found")
        return
    print("SUMMARY Metrics")
    for metric in flow_metrics_list:
        count = 0
        for flow in flow_list:
            if (metric in flow.keys()) and (flow[metric] is not None):
                count += 1
                flow_counts[metric] += flow[metric]
        flow_counts[metric+"count"] = count
        if (count > 0):
            if ("bytes" in metric):
                unit = "bytes"
                if (flow_counts[metric]/count > 1024):
                    unit = "kbps"
                    flow_counts[metric] = flow_counts[metric] / 1024
                if (flow_counts[metric]/count > 1024):
                    unit = "mbps"
                    flow_counts[metric] = flow_counts[metric] / 1024
                if (flow_counts[metric]/count > 1024):
                    unit = "gbps"
                    flow_counts[metric] = flow_counts[metric] / 1024
                if (flow_counts[metric]/count > 1024):
                    unit = "tbps"
                    flow_counts[metric] = flow_counts[metric] / 1024
                print(" Average",metric,":",str(round(flow_counts[metric]/count,3)),unit)
            else:
                print(" Average",metric,":",str(round(flow_counts[metric]/count,3)))
        else:
            print(" Average",metric,": 0 (No Data)")
        
    priority_keys = ['priority_class-0', 'priority_class-1', 'priority_class-2','priority_class-3','priority_class-4']
    ###Get Flow Priorities
    for flow in flow_list:
        priority_class_value = flow['priority_class']
        priority_class_key = 'priority_class-' + str(priority_class_value)
        if priority_class_key not in priority_keys:
            flow_counts[priority_class_key] = 0
            priority_keys.append(priority_class_key)
        flow_counts[priority_class_key] += 1
    print(" ")
    for priority in priority_keys:
        print(" Flows with Priority",priority,":",flow_counts[priority])
    








        





    ####CODE GOES ABOVE HERE#########

if __name__ == "__main__":
    ###Get the CLI Arguments
    CLIARGS = parse_arguments()
    
    ###Authenticate
    SDK = authenticate(CLIARGS)
    
    ###Run Code
    go(SDK, CLIARGS)

    ###Exit Program
    logout(SDK)
