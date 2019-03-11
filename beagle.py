#!/usr/bin/python3
import argparse, os.path
from subprocess import PIPE, run
from netaddr import IPNetwork
from lib import logger
from smb.SMBConnection import SMBConnection
from scapy.all import *

parser = argparse.ArgumentParser(description="Release the bagels.")
parser.add_argument("-t", "--target", required=True, metavar="", help="Takes single IP, CIDR or file.")
parser.add_argument("-m", "--mode", metavar="", help="Host discovery options: ICMP, Port, Skip")
parser.add_argument("-e", "--enumerate", metavar="", help="Enumerate options: Null, Shares, MS17-010, All.")
parser.add_argument("-p", "--ports", metavar="", help="Ports to scan")
args = parser.parse_args()

def get_targets(targets):

	target_list=[]

	if os.path.isfile(targets) == True:
		with open(targets,'r') as file:
			contents=file.readlines()
			for i in (contents):
				target=i.rstrip()
				target_list.append(target)
			return target_list
	else:
		if "/" in targets:
			try:
				subnet=IPNetwork(targets)
			except:
				print('failed to parse')
				quit()

			for i in subnet:
				tmp_str=str(i)
				last_octet=str(tmp_str.split('.')[3])
				if last_octet == '0' or last_octet == '255':
					pass
				else:
					target_list.append(str(i))
			return target_list		

		else:
			target_list.append(targets)
			return target_list

def error_handle(cmd_out):
	ERRORS=["NT_STATUS_CONNECTION_REFUSED","NT_STATUS_INVALID_NETWORK_RESPONSE","NT_STATUS_INVALID_PARAMETER","NT_STATUS_UNSUCCESSFUL","NT_STATUS_IO_TIMEOUT","NT_STATUS_ACCESS_DENIED","NT_STATUS_LOGON_FAILURE","NT_STATUS_REVISION_MISMATCH","COULD NOT CONNECT","NT_STATUS_HOST_UNREACHABLE","no servers could be reached"]
	val=False
	for error in ERRORS:
		if error in cmd_out:
			val=error #return the error if found
			break
		else:
			val=False #otherwise, return False if no error is found
	return val


def tcp_scan(targets,ports):
	src_port = RandShort()
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	SYNACK = 0x12
	RSTACK = 0x14
	URG = 0x20
	ECE = 0x40
	CWR = 0x80

	alive_hosts=[]

	for target in targets:
		logger.blue('Checking TCP ports: {}'.format(target))
		for port in ports:
			send_syn = sr1(IP(dst=target)/TCP(sport=src_port,dport=port,flags=SYN),verbose=0,timeout=2)
			if send_syn == None:
				logger.red_indent('{}:{} CLOSED'.format(target,port))
			elif(send_syn.haslayer(TCP)):
				if(send_syn.getlayer(TCP).flags == SYNACK):
					send_ack = sr(IP(dst=target)/TCP(sport=src_port,dport=port,flags=RST),verbose=0,timeout=2)
					logger.green_indent('{}:{} OPEN'.format(target,port))
					if target not in alive_hosts:
						alive_hosts.append(target)
				elif (send_syn.getlayer(TCP).flags == RSTACK):
					logger.red_indent('{}:{} CLOSED'.format(target,port))
				elif (send_syn.getlayer(TCP).flags == RST):
					logger.red_indent('{}:{} CLOSED'.format(target,port))
	return alive_hosts


def icmp_scan(targets):
	alive_hosts=[]
	for target in targets:
		logger.blue('Pinging: {}'.format(target))
		resp = sr1(IP(dst=str(target))/ICMP(),timeout=2,verbose=0)
		if resp is None:
			logger.red_indent('{}: Down'.format(target))
		elif(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			logger.red_indent('{}: Down'.format(target))
		else:
			logger.green_indent('{}: Up'.format(target))
			if target not in alive_hosts:
				alive_hosts.append(target)
	return alive_hosts

def hunt_null(targets):
	for target in targets:
		logger.blue('Testing null sessions on {}'.format(target))
		rpc_command_lsaquery='rpcclient -U "" -N {} -c "lsaquery"'.format(target)
		result=run(rpc_command_lsaquery,stdout=PIPE,stderr=PIPE,universal_newlines=False,shell=True)

		if len(result.stdout) > 0 and len(result.stderr) == 0:
			command_output=result.stdout
		elif len(result.stderr) > 0 and len(result.stdout) == 0:
			command_output=result.stderr

		decoded=command_output.decode('utf-8')
		has_error=error_handle(decoded)
		if has_error != False:
			logger.red_indent('Failed to connect to {}'.format(target))
		elif has_error == False:
			logger.green_indent('Successfully connected to {}'.format(target))

def hunt_shares(targets):
	username='brandon.mcgrath'
	password='Password4'
	client_machine_name='dc-win12'
	server_name='servername'
	domain_name='lab.local'
	for target in targets:
		logger.blue('Looking up shares on {}'.format(target))

		server_ip=target
		conn = SMBConnection(username, password,client_machine_name,server_name,domain_name,use_ntlm_v2=True,is_direct_tcp=True)
		try:
			conn.connect(server_ip,445)
			logger.green_indent('Successfully connected to {}'.format(server_ip))
			try:
				shares=conn.listShares(timeout=15)
				for share in range(len(shares)):
					logger.green_indent(shares[share].name)
			except Exception as e:
				logger.red_indent('Got error: {}'.format(e))
		except:
			logger.red_indent('Failed to connect to {}'.format(server_ip))




t=get_targets(args.target)

if args.ports:
	p=[]
	ports=args.ports
	if "-" in ports:
		try:
			start=int(ports.split('-')[0])
			end=int(ports.split('-')[1])
			for port in range(start,end+1):
				p.append(port)
		except:
				print('failed to split on "-"')
				quit()
	elif "," in args.ports:
		ports=[int(n) for n in args.ports.split(",")]
		p=ports

else:
	p=[53,88,139,445,464]

logger.blue('Found {} targets'.format(len(t)))

if args.mode.lower() == 'port':
	alive_hosts=tcp_scan(t,p)

elif args.mode.lower() == 'icmp':
	alive_hosts=icmp_scan(t)

elif args.mode == 'skip':
	alive_hosts=t


if args.enumerate == None or args.enumerate.lower() == 'all':
	hunt_null(alive_hosts)
	hunt_shares(t)
	# hunt_ms17(t)
elif args.enumerate.lower() == 'null':
	hunt_null(t)
elif args.enumerate.lower() == 'shares':
	hunt_shares(t)
# elif args.enumerate.lower() == 'ms17-010':
# 	hunt_ms17(t)

else:
	print('the fuck')

