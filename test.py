#!/usr/bin/python

import sys

from os import path
import subprocess
import os
import signal

from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.log import setLogLevel
from mininet.clean import Cleanup
from mininet.node import Controller, RemoteController

import time
import atexit
import signal
import argparse



MODULES = {
       'auth',
       'learningswitch',
       'statelessfirewall',
       'statefulfirewall',
       'firewallmigration',
       'l3statelessfirewall',
       'l3statefulfirewall',
       'l3firewallmigration'
        }

# clean up Floodlight process when done
floodlight_proc = None
def kill_floodlight():
    if floodlight_proc != None:
        os.killpg(os.getpgid(floodlight_proc.pid), signal.SIGTERM)
        print ('Clean up Floodlight program.')

atexit.register(kill_floodlight)


''' Mininet tests for each application
'''
def setup(depth=2, fanout=2):
    Cleanup.cleanup()

    setLogLevel('info')

    topo = TreeTopo( depth=depth, fanout=fanout )
    # net = Mininet( topo=topo, controller=POX(name))
    net = Mininet( topo=topo, controller=None)
    net.addController('c0', controller=RemoteController, ip='0.0.0.0', port=6653)

    net.start()
    return net

def cleanup(net):
    net.stop()
    Cleanup.cleanup()

def firewall_stateful_mn():
    net = setup()

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # h1, h2 are on the port 1 of switch1, so traffic initiating from h1 or h2
    # should be allowed.
    print h1.IP(), h1.cmd('hping3 -c 4', h4.IP())

    # h4 is on the port 2 side of switch 1, but it is seen on previous flows, so
    # now traffic from h4 would also be allowed.
    print h4.IP(), h4.cmd('hping3 -c 4', h2.IP())

    print h2.IP(), h2.cmd('hping3 -c 4', h4.IP())

    # h3 is also from the outside, this traffic should be blocked.
    print h3.IP(), h3.cmd('hping3 -c 4', h2.IP())

    cleanup(net)

def firewall_mn():
    net = setup()

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    print h1.IP(), h1.cmd('hping3 -c 4', h4.IP())
    print h4.IP(), h4.cmd('hping3 -c 4', h2.IP())
    print h2.IP(), h2.cmd('hping3 -c 4', h4.IP())

    cleanup(net)

def learning_mn():
    net = setup()
    net.pingAll()
    cleanup(net)
    
def auth_mn():
    net = setup()

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # Let h4 be the auth server

    # h1 send to h4, get authorized
    print h1.IP(), h1.cmd('hping3 -c 5', h4.IP())

    # h2 send to h4, get authorized
    print h2.IP(), h2.cmd('hping3 -c 5', h4.IP())

    # h1 and h2 should communicate
    print h1.IP(), h1.cmd('hping3 -c 5', h2.IP())

    # h1 and h3 should not communicate
    print h1.IP(), h1.cmd('hping3 -c 5', h3.IP())

    cleanup(net)

def test_module(module, fanout, depth):

    # Start controller
    global floodlight_proc
    cmd = ['java', '-ea -Dlogback.configurationFile=logback.xml',
           '-jar target/floodlight.jar', '-cf src/main/resources/%s.properties' % module]
    print ' '.join( cmd )
    try:
        floodlight_proc = subprocess.Popen(' '.join(cmd), shell=True,
                                           preexec_fn=os.setsid)
        # wait for the POX controller to start
        time.sleep(5)
    except subprocess.CalledProcessError as e:
        print e
        exit(1)

    # Run Mininet simulation

    if module == 'statefulfirewall':
        firewall_stateful_mn()
    elif module == 'firewallmigration':
        firewall_stateful_mn()
    elif module == 'statelessfirewall':
        firewall_mn()
    elif module == 'learningswitch':
        learning_mn()
    elif module == 'auth':
        auth_mn()
    elif module == 'l3firewallmigration':
        firewall_stateful_mn()
    elif module == 'l3statefulfirewall':
        firewall_stateful_mn()
    elif module == 'l3statelessfirewall':
        firewall_mn()
    else:
        assert False, 'Unrecognized controller name: %s.' % module

    # Kill the controller program
    os.killpg(os.getpgid(floodlight_proc.pid), signal.SIGTERM)
    print ('CLean up Floodlight program.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('module', help='POX module name')
    parser.add_argument('--fanout', type=int, default = 2)
    parser.add_argument('--depth', type=int, default = 2)


    args = parser.parse_args()

    if args.module == 'all':
        for m in MODULES:
            print 'Testing module: %s\n#########################\n' % m
            test_module(m, args.fanout, args.depth)
    else:
        test_module(args.module, args.fanout, args.depth)

