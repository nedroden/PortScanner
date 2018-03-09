#!/usr/bin/env python3

import sys
import os
import socket

PORTSCAN_VERSION = '1.0.1'
PORTSCAN_COPYRIGHT = '2017, Robert Monden'

PORT_MAX = 65535
PORT_MIN = 1

terminal_width = os.get_terminal_size().columns


def init():
    print('*** PORT SCANNER ***')
    print('Version: ' + PORTSCAN_VERSION)
    print('Copyright: ' + PORTSCAN_COPYRIGHT)

    arguments = get_args()

    if len(arguments) < 3:
        check_target(arguments[1], all_ports=True)
    else:
        ports = parse_ports(arguments[2])
        check_target(arguments[1], int(ports[0]), int(ports[1]))


def report(message, hasStatus=False, status=True, dots=True):
    global terminal_width

    if hasStatus:
        print(message + '... ' + str('OK' if status else 'FAILED').rjust(terminal_width - (len(message) + 5)))
    elif dots:
        print(message + '...')
    else:
        print(message)


def report_error(message):
    print('  [error] ' + message)
    sys.exit(0)


def get_args():
    if len(sys.argv) < 2:
        report_error('Not enough parameters')

    elif len(sys.argv) > 3:
        report_error('Too many parameters')

    return sys.argv


def parse_ports(ports):
    port_range = ports.split(':')

    if len(port_range) > 2 and len(port_range) < 1:
        report_error('Invalid port range')

    for portnr in port_range:
        if not portnr.isdigit():
            report_error('Ports should be numeric')

        elif int(portnr) > PORT_MAX:
            report_error('Call to nonexisting port. Maximum value: ' + str(PORT_MAX))

        elif int(portnr) < PORT_MIN:
            report_error('Call to nonexisting port. Minimum value: ' + str(PORT_MIN))

    if len(port_range) == 1:
        port_range.append(port_range[0])

    elif port_range[0] > port_range[1]:
        report_error('First port number cannot be higher than the second port number')

    return port_range


def check_port(host, portnr):
    result = -1

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # If the port is open, the return value is 0
        result = s.connect_ex((host, portnr))

        s.close()

    except Exception as e:
        pass

    return result == 0


def check_target(host, min=PORT_MIN, max=PORT_MAX, all_ports=False):
    report('Checking target ' + host)

    found_open_port = False

    try:
        for portnr in range(min, max + 1):
            if check_port(host, portnr):
                report(' !! Found open TCP port: ' + str(portnr))
                found_open_port = True

    except KeyboardInterrupt as e:
        pass

    if not found_open_port:
        print('No open TCP ports found!')


if __name__ == '__main__':
    init()
