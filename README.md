# SR-71- TOR Network reconaissance & Vulnerability Scanner

[![Screenshot](https://i.postimg.cc/TwdWYjTb/2020-07-25-17-14-40-Ubuntu-20-04-Running-Oracle-VM-Virtual-Box.png)](https://postimg.cc/gw70gZXc)

## Current capabilities

- Route all scanning activity through TOR
- Enumerate subdomains
- Scan for web technologies using CERT CERN's WAD 
- Enumerate CVE's related to technologies
- Enumerate CWE's related to CVE's
- Enumerate expired certificates using crt.sh
- Automatically generate HTML reports with findings

## Installation

Follow the steps here to get TOR running on port 9050: https://www.sylvaindurand.org/use-tor-with-python/

`git clone https://github.com/clementbriens/sr-71/`

`pip install -r requirements.txt`

## Usage

After navigating to the `src` folder:

`python run.py -d [DOMAIN]`

Optional arguments:

- `-j` for JSON output of vulnerablities and domain data. Default is false.
- `-q` for quiet mode, supresses output. Default is false.
- `-t` for adjusting request timeouts (in seconds). Default is 5

HTML reports, datasets and plots are generated in the `reports` folder.

## Links

- ASCII Art: https://asciiart.website/index.php?art=transportation/airplanes

- CERN CERT WAD: https://github.com/CERN-CERT/WAD

- Crt.sh: https://crt.sh/

## Todo

- Improve report css
- Elasticsearch output
- Multiprocessing
- Dynamic plots?
- Domain screenshot capability
