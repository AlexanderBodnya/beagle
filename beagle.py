#!/usr/bin/python3

'''
Beagle's objectives:
	1. Identify SMB interactions and list shares
	2. Identify SMB Security
	3. Identify RPC Interactions.
		3a. This will be the --discover flag from Ridder. Ridder will stay as an enumeration tool and Beagle will adopt all discovery functionality.
'''

from smb.SMBConnection import SMBConnection
import argparse
parser = argparse.ArgumentParser(description="Get shares for machine")
parser.add_argument("-t", "--target", required=True, metavar="", help="Host to enumerate")
parser.add_argument("-u", "--username", type=str, metavar="", help="Username to connect with")
parser.add_argument("-p", "--password", metavar="", help="Password to connect with")
parser.add_argument("-d", "--domain", metavar="", help="Domain to connect with")
parser.add_argument("-r", "--recursive", action="store_true", help="Recursively look through shares")
args = parser.parse_args()

if args.username:
	username = args.username
else:
	username=""

if args.password:
	password = args.password
else:
	password=""

client_machine_name = 'dc-win12'
server_name = 'servername'
server_ip = args.target

if args.domain:
	domain_name = args.domain
else:
	domain_name = "WORKGROUP"

conn = SMBConnection(username, password,client_machine_name,server_name,domain_name,use_ntlm_v2=True,is_direct_tcp=True)
conn.connect(server_ip, 445)

shares = conn.listShares(timeout=30)  # obtain a list of shares
for i in range(len(shares)):  # iterate through the list of shares
	print(shares[i].name)

if args.recursive:
	for i in range(len(shares)):
		files = conn.listPath(shares[i].name,'/',timeout=30)
		print(client_machine_name + ':' + shares[i].name)
		for i in range(len(files)):
			print('\t'+files[i].filename)

conn.close()
