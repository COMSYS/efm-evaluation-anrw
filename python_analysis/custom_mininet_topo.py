"""Custom topology example
Three directly connected switches plus a host for each switch:
   h1 --- s1 --- s2 --- s3 --- h2
"""

from mininet.topo import Topo

class MyTopo( Topo ):

    def build( self ):
        # Add hosts and switches
        leftHost = self.addHost( 'h1', ip='10.0.1.1' )
        rightHost = self.addHost( 'h2', ip='10.0.1.2' )

        leftSwitch = self.addSwitch( 's1' )
        middleSwitch = self.addSwitch( 's2' )
        rightSwitch = self.addSwitch( 's3' )

        # Add links
        self.addLink( leftHost, leftSwitch)
        self.addLink( leftSwitch, middleSwitch)
        self.addLink( middleSwitch, rightSwitch)
        self.addLink( rightSwitch, rightHost)

topos = { 'mytopo': ( lambda: MyTopo() ) }