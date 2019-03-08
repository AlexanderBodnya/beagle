#!/usr/bin/python3
import argparse, os.path
from netaddr import IPNetwork
from lib import logger
from smb.SMBConnection import SMBConnection
from scapy.all import *

parser = argparse.ArgumentParser(description="Release the bagels.")
parser.add_argument("-t", "--target", required=True, metavar="", help="Takes single IP, CIDR or file.")
parser.add_argument("-d", "--discovery-mode", metavar="", help="The method for checking if the host is up")
parser.add_argument("-e", "--enumerate", metavar="", help="What the bagels are looking for.")
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
				pass
			elif(send_syn.haslayer(TCP)):
				if(send_syn.getlayer(TCP).flags == SYNACK):
					send_ack = sr(IP(dst=target)/TCP(sport=src_port,dport=port,flags=RST),verbose=0,timeout=2)
					logger.green_indent('{}:{} OPEN'.format(target,port))
					if target not in alive_hosts:
						alive_hosts.append(target)
				elif (send_syn.getlayer(TCP).flags == RSTACK):
					pass
				elif (send_syn.getlayer(TCP).flags == RST):
					pass
	return alive_hosts


def icmp_scan(targets):
	alive_hosts=[]
	for target in targets:
		logger.blue('Pinging: {}'.format(target))
		resp = sr1(IP(dst=str(target))/ICMP(),timeout=2,verbose=0)
		if resp is None:
			pass
		elif(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			pass
		else:
			logger.green_indent('{}: Up'.format(target))
			if target not in alive_hosts:
				alive_hosts.append(target)
	return alive_hosts

def hunt_null(targets):
	for i in targets:
		print(i)

t=get_targets(args.target)
p=[53,88,139,445,464]


logger.blue('Found {} targets'.format(len(t)))

if args.discovery_mode.lower() == 'port':
	alive_hosts=tcp_scan(t,p)

elif args.discovery_mode.lower() == 'icmp':
	alive_hosts=icmp_scan(t)

elif args.discovery_mode == 'skip':
	alive_hosts=t

if args.enumerate.lower() == 'null':
	hunt_null(t)
elif args.enumerate.lower() == 'shares':
	hunt_shares(t)
elif args.enumerate.lower() == 'ms17-010':
	hunt_ms17(t)
elif args.enumerate.lower() == 'all':
	hunt_null(t)
	hunt_shares(t)
	hunt_ms17(t)
else:
	print('the fuck')

