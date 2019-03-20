## Import NMap Results
# This is a Q&D importer of results from NMap.  Takes in an XML file,
# and reformats it to Code Dx results.
# An initialization file is used to specify conditions that indicate error
# in the environment

import argparse
import ConfigParser

import xml.etree.ElementTree as ET
import time
from datetime import date
import re

## getPorts from given IP address
#
# The input values are:
#    a ConfigParser object with the file opened and read
#    an IP address to search for when operating
#
# The values that are obtained are:
#    allowed_ports[] as a list
#    mandatory_ports[] as a list
#    disallowed_ports[] as a list
#
# All are returned in a dictionary with the keywords:
#	 'exists'
#    'allowed'
#    'mandatory'
#    'disallowed'
def getPorts(config, ip) :
	machine_exists = config.has_section(ip)
	allowed_ports = []
	mandatory_ports = []
	disallowed_ports = []
	
	if machine_exists :
		try:
			allowed_ports = config.get(ip, 'allowed_ports')
			allowed_ports = list(allowed_ports.split(' '))
		except ConfigParser.NoOptionError :
			pass

		try:
			mandatory_ports = config.get(ip, 'mandatory_ports')
			mandatory_ports = list(mandatory_ports.split(' '))
		except ConfigParser.NoOptionError :
			pass
		
		try:
			disallowed_ports = config.get(ip, 'disallowed_ports')
			disallowed_ports = list(disallowed_ports.split(' '))
		except ConfigParser.NoOptionError :
			pass
	
	# if all three of the attempts went into the exception handler,
	# mark this host as 'false' as it does not exist
	return { 'exists' : machine_exists, 'allowed' : allowed_ports, 
			 'mandatory' : mandatory_ports,
			 'disallowed' : disallowed_ports,
			 'ip' : ip }
			
## Read Error Definitions
# Decompose the information inside of the configuration file to figure out what
# is and isn't allowed.  We decompose the different lists as such:
#
#	'allowed'    - may or may not be open in the scan
#	'mandatory'  - must be open in the scan
#	'disallowed' - may not be open in a scan
#
def readErrorDefinitions(config) :
	# take the input argumentation and parse the configuration file
	myini = ConfigParser.ConfigParser()
	myini.read(config)
	return myini

## Report Port
# Report the port as an error.  
#
def ReportPort(machine, port, cdx, listname, hostname) :

	# create the subelement that contains the finding
	finding_element = ET.SubElement(cdx, 'finding')
	finding_element.set('severity', 'medium')
	finding_element.set('generator', 'Nmap')
	finding_element.set('type', 'dynamic')
	
	# add a CWE element
	cwe = ET.SubElement(finding_element, 'cwe')
	#cwe.set('id', '1032')
	cwe.set('id', '933')
	
	# Add a tool element
	tool = ET.SubElement(finding_element, 'tool')
	tool.set('name', 'NMap')
	tool.set('category', 'Insecure Configuration')
	#tool.set('code', '') #Am setting this later when we know if the finding
	# is a mandatory port that is not open, or simply disallowed
	
	# Add location if that is necessary
	location_element = ET.SubElement(finding_element, 'location')
	location_element.set('type', 'port')
	location_element.set('path', machine + ":" + port)
	
	# Add description element
	desc_text = ""
	if listname == 'mandatory' :
		desc_text  = "Mandatory port (" + port + ") not open on \""
		desc_text += hostname + "\" (" + machine + ")."
		tool.set('code', 'Unopened Mandatory Port')
	else :
		desc_text  = "Illegal open port (" + port + ")"
		desc_text += " found on server \"" + hostname + "\" (" + machine + ")."
		tool.set('code', 'Illegal Open Port')
		
	desc_element = ET.SubElement(finding_element, 'description')
	desc_element.set('format', 'plain-text')
	desc_element.text = desc_text

## Process Each Port
# We have a machine and findings.  Process each port on the list for this
# machine.  Any ports found that are not on the 'allowed' list are reported
# Any not on the mandatory list are set to be reported.  Mandatory ports that
# are not on the 'allowed' list are set to 'allowed'.
#
# We process all of the ports into a dictionary with the port number as the key.
# Additional information about the port from the scan is also captured.
#
# Each 'mandatory' port is checked.  If present, it is removed from the list
# of ports.  If any mandatory ports remain in the mandatory list that were not
# removed, they are errors.
#
# Each 'allowed' port is checked.  Each 'allowed' port is removed from the list
# as they are detected.
#
# 'disallowed' is currently not used.
#
# The final port list is reported individually as errors if the length is nonzero.
def ProcessEachPort(host, cfg, cdx, hostname) :
	# create a dictionary for the port information 
	portslist = {}
	ports = host.find('ports')
	for port in ports :
		if port.tag != 'port' :
			continue
			
		# we know this is a 'port' tag and not an 'extraports'
		# grab some additional information
		portdict = {}
		portdict['protocol'] = port.get('protocol')
		portdict['reason'] = port.find('state').get('reason')
		
		portservice = port.find('service')
		portdict['product'] = portservice.get('product')
		portdict['xtrainfo'] = portservice.get('extrainfo')
		portdict['name'] = portservice.get('name')
		
		portid = port.get('portid')
		portslist[portid] = portdict
	
	print "The port dictionary has", len(portslist), "elements"

	# loop through the mandatory, and throw out ports on both the mandatory list
	# and the portdict
	for mandatory in cfg['mandatory'] :
		if portslist.has_key(mandatory) :
			# the port exist in both lists.  drop it from the portlist
			portslist.pop(mandatory)
		else :
			# this port is not found and is on the mandatory list.  Report
			# the missing port
			ReportPort(cfg['ip'], mandatory, cdx, 'mandatory', hostname)

	# All of the ports on the 'mandatory' list have been removed, and any not
	# open that are on that list have been reported.  Check to see that the
	# allowed list is properly processed
	for allowed in cfg['allowed'] :
		if portslist.has_key(allowed) :
			portslist.pop(allowed)

	print "After processing, the portslist has", len(portslist), "keys"
	
	# if the ports list is not empty, we have some ports that are open that should not
	# be.  Report all of them.
	print "Reporting", len(portslist), "ports"
	for port in portslist.keys() :
		ReportPort(cfg['ip'], port, cdx, 'not allowed', hostname)
		
	
## ProcessNmapFindings
# Process the host anomaly findings into Code Dx's finding output XML
#
def ProcessNmapFindings(ini, nmap, cdx) :
	# begin by grabbing some statistics from the root of the input XML package
	toolname = nmap.get('scanner')
	profilename = nmap.get('profile_name')
	toolversion = nmap.get('version')
	nmap_args = nmap.get('args')
	
	up_count = 0 	# number of hosts found in the 'up' state
	down_count = 0	# number of hosts found in the 'down' state
	
	# loop through all of the 'host' findings to look for anomalies
	for host in nmap.findall('host') :
		if host.find('status').get('state') == 'down' :
			down_count += 1
			continue
		else :
			up_count += 1
		
		# we have a host that is up.  Grab the config record for it if any exists.
		# No record ignores the findings
		host_ip = host.find('address').get('addr')
		cfg = getPorts(ini, host_ip)
		if not cfg['exists'] :
			continue	# ignore this set of findings as there is no configuration
		
		# compute the first hostname in the incoming records
		try :
			hostname = host.find('hostnames').find('hostname').get('name')
		except :
			hostname = "No Hostname"
		print "Hostname is", hostname
		
		# We have findings, and a machine configuration.  Step through all of
		# the ports that are probed and extract information.
		ProcessEachPort(host, cfg, cdx, hostname)
			
## Main Subroutine
#
def main(args) :
	ini = readErrorDefinitions(args.config)
	nmap_xml = ET.parse(args.in_file).getroot()
	
	# open and begin processing the Code Dx XML output format
	today = date.today()
	report_element = ET.Element('report')
	report_element.set('date', str(today))
	findings_element = ET.SubElement(report_element, 'findings')
	
	# Process each of the "host" findings and report anomalies
	ProcessNmapFindings(ini, nmap_xml, findings_element)
	
	# button up the findings tree and write it out to our output file
	tree = ET.ElementTree(report_element)
	tree.write(args.out_file, xml_declaration=True, encoding='utf-8', method='xml')

## Main Entry Point
#
parser = argparse.ArgumentParser()
parser.add_argument("--in_file",  "-i", required=True, help="Select input XML file.")
parser.add_argument("--out_file", "-o", required=True, help="Select output XML file.")
parser.add_argument("--config",   "-c", required=True, help=".ini filename for configuration")
args = parser.parse_args()

if __name__ == "__main__" :
	main(args)
