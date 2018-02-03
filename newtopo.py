from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


class MyNet( Topo ):    
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )

    # Add switches
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )

        s3 = self.addSwitch( 's3' )

        # Add links
        self.addLink( h1,s1)
        self.addLink( s1,s2)
        self.addLink( s1,s3)
        self.addLink( s2,h2)
        self.addLink( s3,h3)
        

topos = { 'MyNet': ( lambda: MyNet() ) }

