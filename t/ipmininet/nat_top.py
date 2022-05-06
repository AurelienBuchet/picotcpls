from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI
from ipmininet.link import TCIntf
from mininet.log import lg
from mininet.nodelib import NAT
from ipmininet.router.config import RouterConfig, STATIC, StaticRoute
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo

class MyTopology(IPTopo):

    def build(self, *args, **kwargs):
        """
                  --nat---r2---
                /               \
       hostA ---                 --- hostB
                \               /
                  ------r1------
        """

        r1 = self.addRouter("r1", config=RouterConfig,\
                            lo_addresses=["10.50.0.1/24"])
        r2 = self.addRouter("r2", config=RouterConfig,
                            lo_addresses=["10.51.0.1/24"])
        hostA = self.addHost("hostA")
        hostB = self.addHost("hostB")

        #nat = self.addNode('nat', cls=NAT, ip = "10.52.0.1", inNamespace=False)

        ar1 = self.addLink(hostA, r1)
        ar1[hostA].addParams(ip=("130.104.205.174/24"))
        ar1[r1].addParams(ip=("130.104.205.1/24"))

        br1 = self.addLink(hostB, r1)
        br1[hostB].addParams(ip=("130.105.205.174/24"))
        br1[r1].addParams(ip=("130.105.205.1/24"))

        br2 = self.addLink(hostB, r2)
        br2[hostB].addParams(ip=("130.106.205.174/24"))
        br2[r2].addParams(ip=("130.106.205.1/24"))
        #an = self.addLink(hostA, nat)
        #an[hostA].addParams(ip=("130.107.205.174/24"))
        #an[nat].addParams(ip=("130.107.205.1/24"))
        #nr2 = self.addLink(nat, r2)
        #nr2[nat].addParams(ip=("130.108.205.174/24"))
        #nr2[r2].addParams(ip=("130.108.205.1/24"))
        ar2 = self.addLink(hostA, r2)
        ar2[hostA].addParams(ip="130.107.205.174/24")
        ar2[r2].addParams(ip="130.107.205.1/24")

        r1.addDaemon(STATIC, static_routes=[StaticRoute("50.50.50.0/24",\
                                                        "10.1.0.2"),\
                                            StaticRoute("10.2.0.0/24",\
                                                        "10.1.0.2"),\
                                            StaticRoute("100.100.100.0/24",\
                                                        "11.1.0.2"),\
                                            StaticRoute("11.2.0.0/24", "11.1.0.2")])
        r2.addDaemon(STATIC, static_routes=[StaticRoute("50.50.50.0/24",\
                                                        "10.2.0.2"),\
                                            StaticRoute("130.104.205.0/24",\
                                                        "10.1.0.1"),
                                            StaticRoute("42.42.42.0/24",
                                                        "10.1.0.1")])

        super().build(*args, **kwargs)

lg.setLogLevel("info")
net = IPNet(topo=MyTopology(), intf=TCIntf, allocate_IPs=False)
try:
    net.start()
    IPCLI(net)
finally:
    net.stop()