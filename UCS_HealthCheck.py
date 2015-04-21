#!/usr/bin/python

#
# UCS Health Check
#
# Copyright 2015 Rusty Buzhardt and Tighe Kuykendall
#
# Licensed under the Apache License, Version 2.0 (the "License") available
# at  http://www.apache.org/licenses/LICENSE-2.0.  You may not use this
# script except in compliance with the License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Usage:  UCS_Health_Check.py [options]
# -h, --help        Show this help information and exit.
# -i IP, --ip=IP    UCSM IP Address
#

# from pprint import pprint
from UcsSdk import *
from UcsSdk.MoMeta.NetworkElement import NetworkElement
from UcsSdk.MoMeta.TopSystem import TopSystem
from UcsSdk.MoMeta.DomainEnvironmentFeature import DomainEnvironmentFeature
from UcsSdk.MoMeta.EquipmentManufacturingDef import EquipmentManufacturingDef
from UcsSdk.MoMeta.EquipmentChassis import EquipmentChassis 
from UcsSdk.MoMeta.ComputeBlade import ComputeBlade
from UcsSdk.MoMeta.EquipmentIOCard import EquipmentIOCard
from UcsSdk.MoMeta.FirmwareBootUnit import FirmwareBootUnit
from UcsSdk.MoMeta.FaultInst import FaultInst
import os
import getpass
import optparse
import platform

#
# Figure out which platform we're using and how to collect the password
#

def getpassword(prompt):
	if platform.system() == "Linux":
		return getpass.unix_getpass(prompt=prompt)
	elif platform.system() == "Windows" or platform.system() == "Microsoft":
		return getpass.win_getpass(prompt=prompt)
	elif platform.system() == "Macintosh":
		return getpass.unix_getpass(prompt=prompt)
	else:
		return getpass.getpass(prompt=prompt)

def write_html_head():
	html_out.write("<!DOCTYPE html>\
							<html lang=\"en\">\
							<head>\
							<meta charset=\"UTF-8\">\
							<style>\
							body {background-color: #6699FF;\
								font-family: Sans-Serif;\
								font-style: normal;\
							}\
							a:link  {color:#000000;background-color:transparent; text-decoration:none}\
							a:visited {color:#000000; background-color:transparent; text-decoration:none}\
							a:hover   {color:#ff0000; background-color:transparent; text-decoration:underline}\
							a:active  {color:#ff0000; background-color:transparent; text-decoration:underline}\
							h1 {\
								color:black;\
								padding:5px;\
								margin:20px;\
								font-family: Sans-Serif;\
								font-size:200%;\
							}\
							p  {\
								color:black;\
								padding:10px;\
								margin:20px;\
								font-family: Sans-Serif;\
								font-size:100%;\
							}\
							p#border  {\
								color:black;\
								border:1px solid black;\
								padding:10px;\
								margin:20px;\
								font-family: Sans-Serif;\
								font-size:100%;\
							}\
							header  {\
								border:1px solid black;\
								border-color: #CCF;\
								border-radius: 5px;\
								box-shadow: 0 3px 3px rgba(0,0,0,0.3);\
								padding: 0.5em 0.5em 10px 0.5em;\
								margin: 20px;\
								font-family: Sans-Serif;\
								font-size:100%;\
							}\
							article.accordion {\
								border:1px solid black;\
								border-color: #CCF;\
								border-radius: 5px;\
								box-shadow: 0 3px 3px rgba(0,0,0,0.3);\
								padding: 0.5em 0.5em 1px 0.5em;\
								margin: 20px;\
#								margin: 0 auto;\
								display: block;\
#								width: 30em;\
								background-color: #6699FF;\
							}\
							article.accordion section {\
								display: block;\
#								width: 28em;\
								height: 2em;\
								padding: 0 1em;\
								margin: 0 0 0.5em 0;\
								color: black;\
								background-color: #6699FF;\
								overflow: hidden;\
								border-radius: 3px;\
							}\
							article.accordion section h2 {\
								font-size: 1em;\
								font-weight: bold;\
								width: 100%;\
								line-height: 2em;\
								padding: 0;\
								margin: 0;\
								color: black;\
							}\
							article.accordion section h2 a {\
								display: block;\
								width: 100%;\
								line-height: 2em;\
								text-decoration: none;\
								color: inherit;\
								outline: 0 none;\
							}\
							article.accordion section:target {\
								height: 100%;\
								background-color: #6699FF;\
							}\
							article.accordion section:target h2 {\
								font-size: 1.6em;\
								color: black;\
							}\
#							article.accordion section, article.accordion section h2 {\
#								-webkit-transition: all 2s ease;\
#								-moz-transition: all 2s ease;\
#								-ms-transition: all 2s ease;\
#								-o-transition: all 2s ease;\
#								transition: all 2s ease;\
#						   		transition-timing-function: ease-in-out;\
#							}\
							table.border {\
								border: 1px solid black;\
								border-collapse: collapse;\
								text-align: left;\
								vertical-align: center;\
								padding: 15px;\
							}\
							table, th, td {\
								border: 0px solid black;\
								border-collapse: collapse;\
								text-align: left;\
								vertical-align: center;\
								padding: 15px;\
							}\
							th {\
								width: 170px;\
							}\
#							td {\
#								padding:15px;\
#							}\
							</style>\
							<title>UCS Health Check</title>\
							</head>\
							<body>")
	return


#def get_ha_mode(handle):
#	molist = handle.GetManagedObject(None, None, {OrgOrg.DN: "sys"})
#	if (molist != None):
#		for mo in molist:
#			for prop in UcsUtils.GetUcsPropertyMetaAttributeList(mo.propMoMeta.name):
#				if (str(prop) == "Mode"):
#					hamode =  mo.getattr(prop)
#	return hamode

def write_html_fi_open():
	print ""
	print "Fabric Interconnects"
	print ""
	html_out.write("<section id=\"fabricinterconnect\">\
					<h2><a href=\"#fabricinterconnect\">Fabric Interconnect</a></h2>\
					<table class=\"border\">\
					<thead>\
					<tr><th>Fabric Interconnect</th><th>Mgmt Address</th><th>Serial Number</th><th>Model</th><th>Version</th></tr>\
					</thead>\
					<tbody>")
	return 

def write_html_fi_body(fi_name,fi_oobip,fi_serial,fi_model,fi_version):
	html_out.write("<tr>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
					</tr>" % (fi_name, fi_oobip, fi_serial, fi_model, fi_version))
	return

def write_html_iom_open():
	print ""
	print "IO Modules"
	print ""
	html_out.write("<section id=\"iom\">\
					<h2><a href=\"#iom\">IO Module</a></h2>\
					<table class=\"border\">\
					<thead>\
					<tr><th>Chassis ID</th><th>Fabric ID</th><th>Model</th><th>Model</th><th>Version</th></tr>\
					</thead>\
					<tbody>")
	return

def write_html_iom_body(iom_chassisid,iom_switchid,iom_model,iom_serial,iom_runver,iom_prevver):
	html_out.write("<tr>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>Running: %s<br>Backup: %s</td>\
					</tr>" % (iom_chassisid, iom_switchid, iom_model, iom_serial, iom_runver, iom_prevver))
	return

def write_html_chassis_open():
	print ""
	print "Chassis"
	print ""
	html_out.write("<section id=\"chassis\">\
					<h2><a href=\"#chassis\">Chassis</a></h2>\
					<table class=\"border\">\
					<thead>\
					<tr><th>Chassis</th><th>Serial Number</th><th>Model</th></tr>\
					</thead>\
					<tbody>")
	return

def write_html_chassis_body(chassis_name,chassis_serial,chassis_model):
	print ""
	print "Chassis"
	print ""
	html_out.write("<tr>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
					</tr>" % (chassis_name, chassis_serial, chassis_model))	

	return

def write_html_blade_open():
	print ""
	print "Blades"
	print ""
	html_out.write("<section id=\"blade\">\
					<h2><a href=\"#blade\">Blade</a></h2>\
					<table class=\"border\">\
					<thead>\
					<tr><th>Blade</th><th>Serial Number</th><th>Model</th><th>Assigned To</th><th>Memory</th><th>Version</th></tr>\
					</thead>\
					<tbody>")
	return

def write_html_blade_body(blade_name,blade_serial,blade_model,blade_assignedto,blade_memory,blade_runver,blade_prevver):
	print ""
	print "Chassis"
	print ""
	html_out.write("<tr>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
						<td>Running: %s<br>Backup: %s</td>\
					</tr>" % (blade_name, blade_serial, blade_model, blade_assignedto, blade_memory, blade_runver, blade_prevver))
	return

def write_html_tbody_table_section_close():
	html_out.write("</tbody>\
					</table>\
					</section>")
	return

def write_html_domain_open():
	print ""
	print "Domain Information"
	print ""
	return

def write_html_domain_body(domain_name,domain_address,domain_owner,domain_uptime):
	html_out.write("<header>")
	html_out.write("<h1>Domain Name: %s at %s </h1>" % (domain_name, domain_address))
	html_out.write("<p>Owner: %s <br>" % domain_owner)
	html_out.write("Up Time: %s </p>" % domain_uptime)
	return

def write_html_domain_close():
	html_out.write("</header>")
	return

def write_html_end_doc():
	html_out.write("</article>\
					</body>\
					</html>")
	print("")
	print("")
	print("Have a look at the HTML report in the same directory as this script: health_check_report.html")
	print("")
	print("")
	return

def write_html_fault_open():
	print ""
	print "Faults"
	print ""
	html_out.write("<section id=\"fault\">\
					<h2><a href=\"#fault\">Fault</a></h2>\
					<table class=\"border\">\
					<thead>\
					<tr><th>Fault</th><th>Severity</th><th>Description</th></tr>\
					</thead>\
					<tbody>")
	return

def write_html_fault_body(fault_name,fault_sev,fault_desc):
	html_out.write("<tr>\
						<td>%s</td>\
						<td>%s</td>\
						<td>%s</td>\
					</tr>" % (fault_name, fault_sev, fault_desc))
	return

def get_fi(handle):
	key = 1
	for fi in handle.GetManagedObject(None, NetworkElement.ClassId()):
		print "Getting " + fi.Rn
		fi_model = handle.GetManagedObject(None, EquipmentManufacturingDef.ClassId(), {"Pid": fi.Model})
		fi_code = handle.GetManagedObject(None, FirmwareBootUnit.ClassId())
		fi_details[key] = {
			'dev_type' : "FI",
			'name' : fi.Rn,
			'oobip' : fi.OobIfIp,
			'serial' : fi.Serial,
			'model' : fi_model[0].Name.replace("Cisco UCS ", ""),
			'version' : fi_code[0].Version}
		key += 1
	return fi_details

def get_iom(handle):
	key = 1
	for iom in handle.GetManagedObject(None, EquipmentIOCard.ClassId()):
		print "Getting Chassis " + iom.ChassisId + " " + iom.Rn
		iom_model = handle.GetManagedObject(None, EquipmentManufacturingDef.ClassId(), {"Pid": iom.Model})
		iom_code = handle.GetManagedObject(None, FirmwareBootUnit.ClassId())
		iom_details[key] = {
			'dev_type' : "IOM",
			'chassisid' : iom.ChassisId,
			'switchid' : iom.SwitchId,
			'fabricside' : iom.Side,
			'model' : iom_model[0].Name.replace("Cisco UCS ", ""),
			'serial' : iom.Serial,
			'runver' : iom_code[0].Version,
			'prevver' : iom_code[0].PrevVersion}
		key += 1
	return iom_details

def get_chassis(handle):
	key = 1
	for chassis in handle.GetManagedObject(None, EquipmentChassis.ClassId()):
		print "Getting Chassis " + chassis.Dn
		chassis_model = handle.GetManagedObject(None, EquipmentManufacturingDef.ClassId(), {"Pid": chassis.Model})
		chassis_details[key] = {
			'dev_type' : "Chassis",
			'name' : chassis.Dn,
			'serial' : chassis.Serial,
			'model' : chassis_model[0].Name.replace("Cisco UCS ", "")}
		key += 1	
	return chassis_details

def get_blade(handle):
	key = 1
	for blade in handle.GetManagedObject(None, ComputeBlade.ClassId()):
		print "Getting Blade " + blade.Dn
		blade_model = handle.GetManagedObject(None, EquipmentManufacturingDef.ClassId(), {"Pid": blade.Model})
		blade_code = handle.GetManagedObject(None, FirmwareBootUnit.ClassId())
		blade_details[key] = {
			'dev_type' : "Blade",
			'name' : blade.Dn,
			'serial' : blade.Serial,
			'model' : blade_model[0].Name.replace("Cisco UCS ", ""),
			'assignedto' : blade.AssignedToDn,
			'memory' : blade.TotalMemory,
			'runver' : blade_code[0].Version,
			'prevver' : blade_code[0].PrevVersion}
		key += 1
	return blade_details
		
def get_domain(handle):
	key = 1
	for domain in handle.GetManagedObject(None, TopSystem.ClassId()):
		print "Getting Domain " + domain.Name
		domain_details[key] = {
			'name' : domain.Name,
			'address' : domain.Address,
			'owner' : domain.Owner,
			'uptime' : domain.SystemUpTime}
		key += 1
	return domain_details

def get_fault(handle):
	key = 1
	for fault in handle.GetManagedObject(None, FaultInst.ClassId()):
		print "Getting Faults for " + fault.Dn
		fault_details[key] = {
			'name' : fault.Dn,
			'sev' : fault.Severity,
			'desc' : fault.Descr}
		key += 1
	return fault_details


if __name__ == "__main__":
	try:

		#
		# Parse for command line arguments.
		#

		parser = optparse.OptionParser()
		parser.add_option('-i', '--ip', dest="ip", help="UCSM IP Address")
		parser.add_option('-u', '--username', dest="userName", help="Read Only Username For UCS Manager")
		parser.add_option('-p', '--password', dest="password", help="Read Only Password For UCS Manager")
		(options, args) = parser.parse_args()

		#
		#
		# Test Credentials
		#
		# Remove before publishing
		#
		options.ip = "10.90.5.20"
		options.userName = "readonly"
		options.password = "readonly"

		#
		# Print the welcome banner.
		#

		print ""
		print ""
		print "Welcome To The UCS Health Check Script"
		print ""

		#
		# Check for a command line IP, if not prompt for it.
		#

		if options.ip:
			print "Connecting to UCS Manager at address " + options.ip
		elif not options.ip:
			options.ip = raw_input("UCS Manager IP Address: ")

		#
		# Check for a command line username, if not prompt for it.
		#

		if options.userName:
			print "Logging in as " + options.userName
		elif not options.userName:
			options.userName = raw_input("UCS Manager Read Only Username: ")

		#
		# Check for a command line password, if not prompt for it.
		#

		if options.password:
			print "Thanks for providing the password."
		elif not options.password:
			options.password = getpassword("UCS Manager Password: ")

		#
		# Create the connection to the UCS Domain.
		#

		domain_details = {}
		domain_vals = {}
		fi_details = {}
		fi_vals = {}
		iom_details = {}
		iom_vals = {}
		chassis_details ={}
		chassis_vals = {}
		blade_details = {}
		blade_vals = {}
		fault_details = {}
		fault_vals = {}
		
		handle = UcsHandle()
		handle.Login(options.ip, options.userName, options.password)
		handle.StartTransaction()

		#
		# Open the HTML file for writing
		#
		
		html_out = open("health_check_report.html", "w")
		write_html_head()

		#
		# Show Domain information.
		#

		write_html_domain_open()
		get_domain(handle)
		domain_vals = domain_details.items()
		for seq, domain in domain_vals:
			print ("Domain Name: " + domain['name'] + " at address " + domain['address'] + " owned by " + domain['owner'] \
				+ " has been up for " + domain['uptime'])
			write_html_domain_body(domain['name'], domain['address'], domain['owner'], domain['uptime'])
		write_html_domain_close()

		#
		#  Begin colapsed details.
		#

		html_out.write("<article class=\"accordion\">")

		#
		#  Fabric Interconnects
		#

		write_html_fi_open()
		get_fi(handle)
		fi_vals = fi_details.items()
		for seq, fi in fi_vals:			
			print ("FI: " + fi['name'] +\
				"  Address: " + fi['oobip'] +\
				"  SN: " + fi['serial'] +\
				"  Model: " + fi['model'] +\
				"  Version: " + fi['version'])
			write_html_fi_body(fi['name'], fi['oobip'], fi['serial'], fi['model'], fi['version'])
		write_html_tbody_table_section_close()

		#
		#  IO Modules
		#

		write_html_iom_open()
		get_iom(handle)
		iom_vals = iom_details.items()
		for seq, iom in iom_vals:
			print ("Chassis ID:" + iom['chassisid'] +\
				" Fabric ID: " + iom['switchid'] + " ("+ iom['fabricside'] + ")" +\
				" Model: " + iom['model'] +\
				" Serial: " + iom['serial'] +\
				" Running Ver: " + iom['runver'] +\
				" Previous Ver: " + iom['prevver'])
			write_html_iom_body(iom['chassisid'], iom['switchid'], iom['model'], iom['serial'], iom['runver'], iom['prevver'])
		write_html_tbody_table_section_close()

		#
		#  Chassis
		#

		write_html_chassis_open()
		get_chassis(handle)
		chassis_vals = chassis_details.items()
		for seq, chassis in chassis_vals:
			print ("Name: " + chassis['name'] +\
				" Serial Number: " + chassis['serial'] +\
				" Model: " + chassis['model'])
#			html_out.write("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (chassis.Dn, chassis.Serial, chassis.Model))
			write_html_chassis_body(chassis['name'], chassis['serial'], chassis['model'])
		write_html_tbody_table_section_close()

		#
		#  Blades
		#

		write_html_blade_open()
		get_blade(handle)
		blade_vals = blade_details.items()
		for seq, blade in blade_vals:
			print ("Name: " + blade['name'] +\
				" Serial Number: " + blade['serial'] +\
				" Model: " + blade['model'] +\
				" Assigned To: " + blade['assignedto'] +\
				" Memory: " + blade['memory'] +\
				" Running Version: " + blade['runver'] +\
				" Backup Version: " + blade['prevver'])
			write_html_blade_body(blade['name'], blade['serial'], blade['model'], blade['assignedto'], blade['memory'], blade['runver'], blade['prevver'])
		write_html_tbody_table_section_close()
		
		
		#
		#  Faults
		#

		write_html_fault_open()
		get_fault(handle)
		fault_vals = fault_details.items()
		for seq, fault in fault_vals:
			print ("Name: " + fault['name'] +\
				"  Severity: " + fault['sev'] +\
				"  Desc: " + fault['desc'])
			write_html_fault_body(fault['name'], fault['sev'], fault['desc'])
		write_html_tbody_table_section_close()

		#
		#  Close HTML Doc
		#

		write_html_end_doc()
		html_out.close()

		#
		#  Close the UCS connection.
		#

		handle.CompleteTransaction()
		handle.Logout()

		#
		# End of the Health Check Script
		#

	except Exception, err:
		print "Exception:", str(err)
		import traceback
		import sys
		print '-'*60
		traceback.print_exc(file=sys.stdout)
		print '-'*60
		handle.Logout()
