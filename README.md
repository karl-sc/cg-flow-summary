CloudGenix Flow Summary Report
---------------------------------------
This program displays summary statistics for flow data given a Site Name, Time Period, Application, and Source IP
If either Application or Source IP are not given, we will implicitly assume all APP's or Source IP's and not 
filter flows based on it.
```
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
```

# EXAMPLES:
    Show todays flows for the past 1 hour for all source-ip's and apps at chicago
        cg-flow-summary.py --authtokenfile ~/token-karl-demopod1.txt --site-name chicago

    Show 8-hours of flow summary for New York from yesterday. Authentication will be handled interactively.
        cg-flow-summary.py -s york -d 1 -p 8

    Show 24-hours of flow summary data for New York Branch from 7 days ago for a 24 hour period for the 
    app Dropbox and the source HOST IP of 192.168.20.102.
        cg-flow-summary.py --authtokenfile ~/token-karl-demopod1.txt -s york -d 7 -p 24 -a dropbox -i 192.168.20.102/32

# NOTES:
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
