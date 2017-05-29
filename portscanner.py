#!/usr/bin/env python3
import sys
import os
import socket

portscan_version = '1.0.0'
portscan_copyright = '2017, Robert Monden'

port_max = 65535

terminal_width = os.get_terminal_size().columns


def init():
	print ('*** PORT SCANNER ***')
	print ('Version: ' + portscan_version)
	print ('Copyright: ' + portscan_copyright)

	arguments = get_args()

	if len(arguments) < 3:
		check_target(arguments[1], all_ports=True)
	else:
		ports = parse_ports(arguments[2])
		check_target(arguments[1], int(ports[0]), int(ports[1]))


def report(message, hasStatus = False, status = True, dots = True):
	global terminal_width

	if hasStatus:
	    print (message + '... ' + str('OK' if status else 'FAILED').rjust(terminal_width - (len(message) + 5)))
	elif dots:
	    print (message + '...')
	else:
		print (message)


def report_error(message):
	print ('  [error] ' + message)
	sys.exit(0)


def get_args():
	if len(sys.argv) < 2:
		report_error('Not enough parameters')
	elif len(sys.argv) > 3:
		report_error('Too many parameters')

	return sys.argv


def parse_ports(ports):
	port_range = ports.split(':')

	if not len(port_range) == 2:
		report_error('Invalid port range')

	elif not port_range[0].isdigit() or not port_range[1].isdigit():
		report_error('Ports should be numeric')

	elif int(port_range[0]) > port_max or int(port_range[1]) > port_max:
		report_error('Call to nonexisting port. Maximum value: ' + str(port_max))

	return port_range


def check_port(host, portnr, tcp = True):
	result = -1

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		result = s.connect_ex((host, portnr))

		s.close()

	except Exception as e:
		pass

	return result == 0


def check_target(host, min = 0, max = port_max, all_ports = False):
	report('Checking target ' + host)

	found_open_port = False

	try:
		for portnr in range(min, max + 1):
			if check_port(host, portnr, True):
				report(' !! Found open TCP port: ' + str(portnr))
				found_open_port = True

	except KeyboardInterrupt as e:
		pass

	if not found_open_port:
		print ('No open ports found!')

	return

	print ('Scan for UDP ports (warning: will take time)? [Y/n] ', end='')
	key = input()

	if key.strip().lower() == 'y':
		found_open_port = False

		try:
			for portnr in range(min, max + 1):
				if check_port(host, portnr, False):
					report(' !! Found open UDP port: ' + str(portnr))
					found_open_port = True

		except KeyboardInterrupt as e:
			pass

		if not found_open_port:
			print ('No open ports found!')


if __name__ == '__main__':
	init()