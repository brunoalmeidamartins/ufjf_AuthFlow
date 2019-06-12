#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    controller=net.addController(name='controller',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    # S1
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac='00:00:00:00:00:01', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac='00:00:00:00:00:02', defaultRoute=None)
    # S2
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', mac='00:00:00:00:00:03', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', mac='00:00:00:00:00:04', defaultRoute=None)
    # S3
    srv1 = net.addHost('srv1', cls=Host, ip='10.0.0.10', mac='00:00:00:00:00:10', defaultRoute=None)
    srv2 = net.addHost('srv2', cls=Host, ip='10.0.0.12', mac='00:00:00:00:00:12', defaultRoute=None)
    auth = net.addHost('auth', inNamespace=False, cls=Host, ip='10.0.0.11', mac='00:00:00:00:00:11', defaultRoute=None)

    info( '*** Add links\n')
    # S1
    net.addLink(s1, h1, 1, 1)
    net.addLink(s1, h2, 2, 1)
    # S2
    net.addLink(s2, h3, 1, 1)
    net.addLink(s2, h4, 2, 1)
    # S3
    net.addLink(s3, srv1, 1, 1)
    net.addLink(s3, srv2, 2, 1)
    net.addLink(s3, auth, 3, 1)

    #Ligacao entre swithcs
    net.addLink(s1, s3, 3, 4)
    net.addLink(s2, s3, 3, 5)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s3').start([controller])
    net.get('s2').start([controller])
    net.get('s1').start([controller])

    info('*** Adicionando Rotas\n')
    h1.cmd('route add default dev h1-eth1')
    h2.cmd('route add default dev h2-eth1')
    h3.cmd('route add default dev h3-eth1')
    h4.cmd('route add default dev h4-eth1')
    srv1.cmd('route add default dev srv1-eth1')
    srv2.cmd('route add default dev srv2-eth1')
    auth.cmd('route add default dev auth-eth1')


    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

