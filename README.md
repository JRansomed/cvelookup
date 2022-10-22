# cvelookup
cvelookup is a python3 script used to lookup CVEs from nvd.nist.gov via version 2.0 of their API.  It performs lookups through a user prompt or bulk lookups by extracting CVEs from PDF or text files.  

## Getting started (A high level overview)
There are multiple ways to use this script.  This is an example of one way to use it.  

### Start by cloning this repo:
`git clone https://git.jransomed.com/jstevens/cvelookup.git`  

The following files will be downloaded:  
 **README.md:** This is a copy of the README displayed on this repo  
**cvelookup-samplewrapper:** This is a sample wrapper you can use to leverage a virtual environment with cvelookup  
 **cvelookup.ini:** cvelookup's configuration file.  More on this further into this document.  
 **cvelookup.py:** cvelookup script  
 **requirements.txt:** This file lists the requirements/prerequisites that need to be installed.  

### Create virtual environment
Navigate into the cloned cvelookup folder, then create your virtual environment:  
`python3 -m venv venv`  
This will create a virtual environment folder named *venv* in the cvelookup repo folder.  

### Install requirements/prerequisites
Activate the virtual environment:  
`source venv/bin/activate`
Use pip3 to install the required packages:  
`pip3 install -r requirements.txt`

### Setup *cvelookup.ini*
Copy the *cvelookup.ini* file to your home directory and rename it to *.cvelookup.ini*  
The cvelookup.ini file is used to configure the following:  
*apikey:* If you have an API key for nvd.nist.gov, add it here.  
*cvssmin:* This is the minumum CVSS version that will be returned in the search results.  Lower Base Scores will be ignored  
*searchdelay:* This is the delay in seconds between CVE lookups.  The default is 7.  Nist.gov does employ rate limits.  

### Setup *cvelookup-wrapper*
This optional wrapper helps activate the virtual environment, execute the script, and exit the virtual environment.  
Copy *cvelookup-wrapper* somewhere that is in your PATH.  Rename it to something like *cvelookup*.  Edit it so that it has has the correct paths to your cvelookup repo.  

**Alternative to the wrapper**:
An alternative to the wrapper is an alias with your shell. For bash, you'd edit .bashrc in your home directory and add something like the following that points to your installation:  
`alias cvelookup="~/src/cvelookup/venv/bin/python3 ~/src/cvelookup/cvelookup.py"`  

To use the new alias, restart your terminal or source it again:  
`source ~/.bashrc`

## cvelookup.py usage help:
```
cvelookup -h
Usage: cvelookup.py [OPTIONS]

  A tool to lookup CVEs.

Options:
  -f TEXT     Specify a file to perform a bulk search of any CVEs found within
              the file.
  -l          Lookup CVEs manually
  -h, --help  Show this message and exit.
  ```

## Additional Information
cvelookup was created out of necessity to help with checking CVEs for my work.  I am not a programmer and am learning though doing.  I am sure it could be greatly improved upon and provide it as-is.
