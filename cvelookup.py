#!/usr/bin/env python3

import click
import fitz
import re
import requests
import sys
import textwrap
import time
from configparser import ConfigParser
from pathlib import Path
from urllib.parse import quote as urlencode


# User textwrap to cleanup the description output.  Limit to 50 characters
# wide and prevents wrapping in the middle of words.
wrapper = textwrap.TextWrapper(width=50)


# Process the config file and set our options
# Get API key from .cvelookup.ini
inifile = str(Path.home()) + '/.cvelookup.ini'
config = ConfigParser()
config.read(inifile)

# Get the API key, If a config file hasn't been created, set apikey to None
# CVSS miniumum to MEDIUM, and searchdelay to 7
if not config.sections():
    apikey = None
    cvssmin = 'MEDIUM'
    searchdelay = int(7)
else:
    apikey = config['main'].get('apikey')
    cvssmin = config['main'].get('cvssmin')
    searchdelay = int(config['main'].get('searchdelay'))

# API address
url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'


def bulkreport(bresults):
    # bresults has been returned to us from cvebulk() as a list that contains:
    # cvefailed (a list)
    # cveresults (a dictionary with our CVEs)
    # The returned list is as follows: [cvefailed, cveresults]
    # For bulkreport, we are interested in the cveresults dictionary, so we
    # store that dictionary as bresults

    bresults = bresults[1]

    cvereport = open('cvereport.txt', 'w')

    # Begin logic to match CVSS results based on our minimum requirement.
    # Default is MEDIUM. This can be changed in .cvelookup.ini
    if cvssmin == 'MEDIUM':
        for cve, details in bresults.items():
            if (details[0]['cvss2'] == 'MEDIUM'
                    or details[0]['cvss2'] == 'HIGH'
                    or details[0]['cvss2'] == 'CRITICAL'
                    or details[0]['cvss3'] == 'MEDIUM'
                    or details[0]['cvss3'] == 'HIGH'
                    or details[0]['cvss3'] == 'CRITICAL'):
                writereport(cve, details)
    elif cvssmin == 'HIGH':
        for cve, details in bresults.items():
            if (details[0]['cvss2'] == 'HIGH'
                    or details[0]['cvss2'] == 'CRITICAL'
                    or details[0]['cvss3'] == 'HIGH'
                    or details[0]['cvss3'] == 'CRITICAL'):
                writereport(cve, details)
    elif cvssmin == 'CRITICAL':
        for cve, details in bresults.items():
            if (details[0]['cvss2'] == 'CRITICAL'
                    or details[0]['cvss3'] == 'CRITICAL'):
                writereport(cve, details)


def cvebulk(cvelist):
    """
    Function to perform bulk searches of CVEs. This function will check to see
    if an API key has been configured in .cvelookup.ini in the user's home
    directory.
    """

    cvefailed = []
    cveresults = {}

    # Begin loop to lookup CVEs. Nist.gov has lookup rate limits.
    # With an API key: 50 requests in a rolling 30 second window
    # Without an API key: 5 requests in a rolling 30 second window
    # To play it safe, we default a 7 second delay for lookups. If we have a
    # failure, we wait 30 seconds and try again.  We store the failed entries
    # so we can notify the user of them in a final report. Nist does not
    # recommend attempting the requests but every several seconds.
    for cve in cvelist:
        if cve.startswith('CVE'):
            print('Retrieving: ' + cve)
            results = nistsearch(apikey, url, cve)

            # Test and see if we successfully got results back from NIST.
            # Currently, an exception has been added to handle exceeding
            # the rate limits.
            try:
                results = results.json()
            except Exception as e:
                if 'Forbidden' in str(e):
                    print('ERROR: Got a 403 Forbbiden response. This is most'
                          '\n       likely a rate limit violation. We will'
                          ' add\n       a delay and try again. See the '
                          'error details\n       below:\n')
                    print('*********************************************')
                    print(e)
                    print('*********************************************\n\n')
                    results = {'totalResults': 0}
            
            # Sometimes we get an unexpected response from nist.gov.
            # Waiting a little bit and trying the request again normally
            # clears the issue up.  We will wait 30 seconds and try again.
            # If it fails for the second attempt, note the failed CVE.
            if (getresults(results) == 0):
                print('ERROR: Couldn\'t retrieve: ' + cve + '\n' +
                      'ERROR: Waiting 30 seconds and retrying...')
                time.sleep(30)
                results = nistsearch(apikey, url, cve)
                results = results.json()
                if (getresults(results) == 0):
                    print('ERROR: Failed to retrieve: ' + cve)
                    cvefailed.append(cve)
                    time.sleep(searchdelay)
                else:
                    print('Adding results')
                    cveresults.update(
                            {cve:
                                [{'cvss2': getcvss2(results),
                                    'cvss3': getcvss3(results),
                                    'Description': getdesc(results)
                                  }
                                 ]
                             }
                        )
                    time.sleep(searchdelay)
            else:
                cveresults.update(
                        {cve:
                            [{'cvss2': getcvss2(results),
                                'cvss3': getcvss3(results),
                                'Description': getdesc(results)
                              }
                             ]
                         }
                    )
                time.sleep(searchdelay)
    return cvefailed, cveresults


def cvesearch():
    """
    Function to search for CVEs, one at a time.  The function will run in a
    loop, asking for a CVE to lookup, return the details and ask for another
    CVE to lookup. The prompt will inform the user that pressing the 'q' key
    will exit the search.
    """

    while (True):
        ucve = input('\nEnter CVE or q to quit: ')
        if ucve == 'q':
            sys.exit('\n\nQuit was selected, exiting...\n\n')
        else:
            if ucve.startswith('cve') or ucve.startswith('CVE'):
                results = nistsearch(apikey, url, ucve)
                results = results.json()
                print('\n\n===============')
                print(ucve)
                print('===============\n')
                print('CVSSv2: ' + getcvss2(results))
                print('CVSSv3: ' + getcvss3(results) + '\n')
                print('DESCRIPTION:')
                print(wrapper.fill(text=getdesc(results)) + '\n\n')
                print('Observing a search delay of ' + searchdelay +
                      ' seconds...')
                time.sleep(searchdelay)


def extract(filename):
    """
    This function extracts CVEs from a PDF file.  It does a simple regex
    against the text it pulls from the pages.  Regex matches are written to a
    file named cves.txt
    """
    pages = []
    cvelst = set()
    templst = []

    cvepattern = r'(?i)CVE\S\d{4}\S\d{4,7}'

    # Check if the file is a PDF
    pdfcheck = '.pdf'
    if pdfcheck in filename.lower():
        pdf = fitz.open(filename)
        for page in pdf:
            templst.extend(re.findall(cvepattern, page.get_text()))
    else:
        # Not a PDF, treat as a plain text file
        with open(filename) as tfile:
            tcontent = tfile.read()
        templst = re.findall(cvepattern, tcontent)

    for cve in templst:
        # Aruba's PDFs use a weird hyphen, replace it with a normal hyphen
        # In many terminals and editors, the hyphens below look the same, but
        # they are not
        cve = cve.replace('‑', '-')
        cvelst.add(cve.upper())

    return cvelst


def failreport(bresults):
    """
    This function will generate the filed CVEs report and present to the user.

    bresults has been returned to us from cvebulk as a list that contains:
    cvefailed (a list)
    cveresults (a dictionary with our CVEs)

    The returned list is as follows: [cvefailed, cveresults]
    """

    # For failreport, we are interested in the cvefailed list, so we
    # store that list as bresults
    bresults = bresults[0]

    if (bresults):
        print('\n\n***There were some errors during the bulk search.***')
        print('The following CVEs were not able to be retrieved:')
        for cve in bresults:
            print(cve)


def getcveid(results):
    """
    This function will parse the retrieved data and extract the CVE ID that the
    returned data is applies to and return the CVE ID. This function is not
    currently in use. It is here for debugging purposes.
    """

    try:
        return results['vulnerabilities'][0]['cve']['id']
    except (KeyError, NameError):
        return None


def getcvss2(results):
    """
    This function will parse the retrieved data for the CVSSv2 base severity
    and return it.
    """

    try:
        return results['vulnerabilities'][0]['cve']['metrics'][
                'cvssMetricV2'][0]['cvssData']['baseSeverity']
    except (KeyError, NameError):
        return 'Unknown'


def getcvss3(results):
    """
    This function will parse the retrieved data for the CVSSv3 base severity
    and return it.
    """

    try:
        return results['vulnerabilities'][0]['cve']['metrics'][
                'cvssMetricV31'][0]['cvssData']['baseSeverity']
    except (KeyError, NameError):
        return 'Unknown'


def getdesc(results):
    """
    This function will parse the retrieved data for the CVE description and
    return it.
    """

    try:
        return results['vulnerabilities'][0]['cve']['descriptions'][0]['value']
    except (KeyError, NameError):
        return 'Unknown'


def getresults(results):
    """
    This function will parse the retrieved data and extract the total returned
    results.  If this number is 0, it will mean we did not get any results for
    our search.  This is used to determine if the search failed. If the data
    is corrupt, return a 0.
    """

    try:
        return results['totalResults']
    except (KeyError, NameError):
        return 0


def nistsearch(apikey, url, cve):
    """
    Function to perform the API search to nvd.nist.gov.
    """

    headers = {
            'apiKey': apikey
            }

    if apikey:
        return requests.get(url + urlencode('?cveID=') + cve, headers=headers)
    else:
        return requests.get(url + urlencode('?cveID=' + cve))


def printsettings(apikey, cvssmin, searchdelay):
    """
    Function to display the current settings for cvelookup:
    API Key: Enabled or Disabled
    CVSS Minimum Rating: Currently configured minumum rating
    Search Delay: Currenlty configured search delay

    This function is used at the start of the bulksearch
    """

    print('\n\n================================================')
    print('cvelookup is running with the following options:')
    if apikey:
        print('API Key: Enabled')
    else:
        print('API Key: Disabled')
    print('CVSS Minimum Rating: ' + cvssmin)
    print('Search Delay: ' + str(searchdelay) + ' seconds')
    print('================================================\n\n')


def writereport(cve, details):
    """
    Function to write the CVE data that has been retrieved into a text file.
    The text file will be created at the location cvelookup was executed from.
    """

    cvereport = open('cvereport.txt', 'a')
    cvereport.write('===============\n' + cve + '\n===============\n\n')
    cvereport.write('CVSSv2: ' + details[0]['cvss2'] + '\n')
    cvereport.write('CVSSv3: ' + details[0]['cvss3'] + '\n\n')
    cvereport.write('DESCRIPTION: \n')
    cvereport.write(wrapper.fill(text=details[0]['Description']))
    cvereport.write('\n\n\n')
    cvereport.close()


# Click configurations. Click is used to render the usage information and to
# setup the arguments that can be used and processed.
CONTEXT_SETTINGS = {'help_option_names': ['-h', '--help']}


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-f', required=False, help='Specify a file to perform a bulk ' +
              'search of any CVEs found within the file.')
@click.option('-l', required=False, is_flag=True, help='Lookup CVEs manually')
def main(f, l):
    '''
    A tool to lookup CVEs.
    '''
    if f:
        printsettings(apikey, cvssmin, searchdelay)
        cvelist = extract(f)
        bresults = cvebulk(cvelist)
        bulkreport(bresults)
        failreport(bresults)
        print('\n\nThe results of your search have been saved in a filed ' +
              'named:')
        print('cvereport.txt\n')
        print('The file can be found in the location you executed cvelookup')
        print('from.\n\n')
        pass
    elif l:
        cvesearch()
    else:
        print('Usage: cvelookup.py [OPTIONS] \n' +
              "Try 'cvelookup.py -h' for help.\n\n")


if __name__ == '__main__':
    main()
