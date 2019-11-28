# Escalating TPLink Firmware Vulnerabilities
Script to search for a vulnerability patron in multiples Firmwares using Ghidra Scripting and Binwalk to extract httpd binary in an automatically way

This tool was designed to search for a vulnerability patron previously identified in multiples httpd - Web Servers Binaries through multiples firmwares in an automated way.

This tool can be modified to identify vulnerable patrons in diferent vendors firmwares and also in diferent binaries (not only httpd)
this can  be done through the modification or creation of new Ghidra Scripts that define the vulnerable patron to look for.

## httpd_extractor.py
This script will extract the httpd binaries in all the firmwares stored in **Firmwares** folder and will stored into **HTTPD_Binaries** folder.

## analyzer.py
This script will run Ghidra headless analyser in conjuction with the Script stored in **Ghidra_Scripts** folder to identify vulnerability patrons in all the HTTPD Binaries extracted by **httpd_extractor.py**

This script will create pdf files with a map of function called that identify the vulnerable patron and will store that resuts in the folder **Analysis_Results**

### With this tool I was able to identify that the following devices are affected by CVE-2018-16119 (Authenticated Remote Code Execution) vulnerability that I found in 2018.

## Affected Devices
* TP-LINK WR710
* TP-LINK WDR3500
* TP-LINK Archer C7
* TP-LINK Archer C5
* TP-LINK WR1043ND
* TP-LINK WDR4900

Using Zoomeye.org I was able to determinate that there is a total of **106.966 devices (aprox)** vulnerables exposed to Internet.
