# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.
  
"""
A shortest-path forwarding application.
  
This is a standalone L2 switch that learns ethernet addresses
across the entire network and picks short paths between them.
  
You shouldn't really write an application this way -- you should
keep more state in the controller (that is, your flow tables),
and/or you should make your topology more static.  However, this
does (mostly) work. :)
  
Depends on openflow.discovery
Works with openflow.spanning_tree
"""
  
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr
from time import clock
import sys
from termcolor import colored, cprint
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.of_json import *
from pox.openflow.discovery import Discovery
import math
from detect import Entropy
from time import clock
from datetime import datetime

#ent_obj = Entropy()
sent_sw = []
count = 0
ipList = []
path_for_stat = []
 
log = core.getLogger()
  
# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))
  
# Switches we know of.  [dpid] -> Switch
switches = {}
  
# ethaddr -> (switch, port)
mac_map = {}
  
# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))
  
# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}
  
# Time to not flood in seconds
FLOOD_HOLDDOWN = 5
  
# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30
  
# How long is allowable to set up a path?
PATH_SETUP_TIME = 4
  
  
def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """
  
  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print
  
  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate
  
  #dump()
  
  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)
  
  #print "--------------------"
  #dump()
  
  
def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)
  
  
def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports
  
  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[2]:
      return False
  return True
  
  
def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]
  
  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))
  
  assert _check_path(r), "Illegal path!"
  
  return r
  
  
class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet
  
    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()
  
  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self
  
  @property
  def is_expired (self):
    return time.time() >= self.expires_at
  
  def notify (self, event):
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)
  
      core.l2_multi.raiseEvent(PathInstalled(self.path))
  
  
  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))
  
  
class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    Event.__init__(self)
    self.path = path
  
  
class Switch (EventMixin):

  entDic = {}
  dstEnt = []
  all_ip = {}
  max_path = []
  entc = 0
  start_time = 0
  end_time = 0
  ftimer = 0
  count = 0  

  def statcolect(self, element):

    global count
    global ipList
    global my_start
    global my_end
    global attack
    #attackswitch = {}
    #global ent_threshold = 1
    ent = 0
    #value = 1
    l = 0
    self.start_time = datetime.now()
    my_start = clock()
    #print " The start time is", my_start
    count += 1
    ipList.append(element)
    if count == 50:
      for i in ipList:
        l += 1
        if i not in self.entDic:
          self.entDic[i] = 0
        self.entDic[i] += 1
      self.entc = self.entropy(self.entDic)
      #log.info(self.entDic)
      self.entDic = {}
      ipList = []
      l = 0
      count = 0
      ent = self.entc
      print '\n'
      print 'entropy =' , self.entc
      self.end_time = datetime.now()
      my_end = clock()- my_start
      #self.ftimer = my_end - my_start
      print "start time", self.start_time
      print "End time", self.end_time
      print " Time taken to calculate entropy", my_end
      print '\n'
      if ent < 1:
        cprint('WARNING!!!!!! Attack Suspected', 'green', 'on_red')
        print '\n'
        self.flow_stat()
      else:
        self.flow_stat()
  def entropy(self, lists):
    l = 50
    elist = []
    #print list.values()
    for p in lists.values():
      c = float(p)/50
      c = abs(c)
      elist.append(-c*math.log(c,2))
      #log.info('Entropy = ')
      #log.info(sum(elist))
      self.dstEnt.append(sum(elist))
    if(len(self.dstEnt))==80:
               print self.dstEnt
               self.dstEnt = []
    self.value = sum(elist)
    ec = sum(elist)
    return ec
                              

  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None
    self.flow_list = 0
    self.start = 0
    self.end = 0
    # Our table
    self.macToPort = {}

    # Our firewall table
    self.firewall = {}

    # Add rules
    self.AddRule('10.0.0.1','10.0.0.1')
    self.AddRule('10.0.0.2','10.0.0.3')
    self.AddRule('10.0.0.3','10.0.0.4')
    self.AddRule('10.0.0.4','10.0.0.5')
    self.AddRule('10.0.0.5','10.0.0.6')
    self.AddRule('10.0.0.6','10.0.0.7')
    self.AddRule('10.0.0.7','10.0.0.2')




  
  def _timer_func (self):
    sent_connection = 0
    for connection in core.openflow._connections.values():
        if dpidToStr(connection.dpid) not in sent_sw:
            #print 'send flow request to switch', dpidToStr(connection.dpid)
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
            sent_connection += 1
            sent_sw.append(dpidToStr(connection.dpid))
            #sent switch list is sent_sw
        else:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
    #print ' sent switch list', sent_sw
    log.debug("Sent %i flow/port stats request(s)", len(core.openflow._connections))
  


  def _handle_flowstats_received (self, event):
    stats = flow_stats_to_list(event.stats)
    #log.info("flow statistics received from %s",dpidToStr(event.connection.dpid))
    flowlist = []
    sw_list = []
    rate = 0
    flow_count = 0
    totalP_count = 0
    totalB_count = 0
    #attackswitch = {}
    for flow in event.stats:
       if flow.match.dl_type==0x0800:
         flowlist.append({"flow_Duration": flow.duration_sec, "packet_count": flow.packet_count, "byte_count": flow.byte_count})
         totalP_count+=flow.packet_count
         totalB_count+=flow.byte_count
         if flow.packet_count <> 0:
            flow_count += 1

    if totalP_count >= 163 and totalB_count >=9025:
       cprint(' Attack Confirmed ', 'blue', 'on_yellow')

    #print'Traffic from switch',dpidToStr(event.connection.dpid),'is',totalB_count,'bytes and',totalP_count,' packet', flow_count, 'flows'
    
    #if totalP_count >= 163 and totalB_count >=9025:
      # print " Attack Confirmed"
          


 
  def flow_stat(self):
    from pox.lib.recoco import Timer
    self._timer_func()

  def __repr__ (self):
    return dpid_to_str(self.dpid)
  
  def _install (self, switch, in_port, out_port, match, buf = None):
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)
  
  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)
  
  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)
  
      import pox.lib.packet as pkt
  
      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)
  
        from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')
  
        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)
  
      return
  
    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))
 
    #self.statcolect(match.nw_dst)
    self.statcolect(match.nw_dst)

 
    # We have a path -- install it
    self._install_path(p, match, event.ofp)
  
    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    self._install_path(p, match.flip())
  
   # function that allows adding firewall rules into the firewall table
  def AddRule (self, dst = 0, src=0,value=True):
      self.firewall[(dst,src)]=value
      log.info("Adding firewall rule")


  # function that allows deleting firewall rules from the firewall table
  def DeleteRule (self, dpidstr, src=0):
     try:
       del self.firewall[(dpidstr,src)]
       log.debug("Deleting firewall rule in %s: %s",
                 dpidstr, src)
     except KeyError:
       log.error("Cannot find in %s: %s",
                 dpidstr, src)


  # check if packet is compliant to rules before proceeding
  def CheckRule (self, dst=0, src=0):
    try:
      entry = self.firewall[(dst, src)]
      if (entry == True):
         pass
         #log.debug("Rule (%s) found in %s: FORWARD",src, dpidstr)
      else:
        log.info("IP (%s) not found in Table : DROP",src)
      return entry
    except KeyError:
      log.info("IP (%s) NOT found in Table: DROP",src)
      return False


  def _handle_PacketIn (self, event):


    packet = event.parsed
    
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)


    self.macToPort[packet.src] = event.port # 1
    # Get the DPID of the Switch Connection
    dpidstr = dpid_to_str(event.connection.dpid)
   
    """
    if packet.type == ethernet.IP_TYPE:
       #print packet.next.dstip
       self.start = time.time()
       time_interval = 3
       self.flow_list+=1
       #ent_obj.statcolect(packet.next.dstip)
       print 'flow', self.flow_list
       if self.flow_list == 1:
          self.end = self.start + time_interval
          #print 'end', self.end
       if self.flow_list > 300 and self.start<self.end:
          cprint(' Attack Confirmed', 'blue', 'on_yellow')
          print '\n'
          if self.CheckRule(dpidstr, packet.src) == False:
             drop()
             return
       elif self.start>=self.end:
             self.flow_list = 0
       else:
             pass
      """

           #print 'flow', self.flow_list

       
       #ent_obj.statcolect(packet.next.dstip)

    #packet = event.parsed
  
    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr
  
    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return
  
    if oldloc is None:
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
      # ethaddr seen at different place!
      if loc[1] not in adjacency[loc[0]].values():
        # New place is another "plain" port (probably)
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].connection.dpid), oldloc[1],
                  dpid_to_str(   loc[0].connection.dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        # New place is a switch-to-switch port!
        #TODO: This should be a flood.  It'd be nice if we knew.  We could
        #      check if the port is in the spanning tree if it's available.
        #      Or maybe we should flood more carefully?
        log.warning("Packet from %s arrived at %s.%i without flow",
                    packet.src, dpid_to_str(self.dpid), event.port)
        #drop()
        #return
  
  
    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        dest = mac_map[packet.dst]
        match = of.ofp_match.from_packet(packet)
        self.install_path(dest[0], dest[1], match, event)
  
  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None
  
  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()
  
  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True
  
  def _handle_ConnectionDown (self, event):
    self.disconnect()
  
  
class l2_multi (EventMixin):
  
  _eventMixin_events = set([
    PathInstalled,
  ])
  
  def __init__ (self):
    # Listen to dependencies
    def startup ():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)
    core.call_when_ready(startup, ('openflow','openflow_discovery'))
  
  def _handle_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])
  
    l = event.link
    sw1 = switches[l.dpid1]
    sw2 = switches[l.dpid2]
  
    # Invalidate all flows and path info.
    # For link adds, this makes sure that if a new link leads to an
    # improved path, we use it.
    # For link removals, this makes sure that we don't use a
    # path that may have been broken.
    #NOTE: This could be radically improved! (e.g., not *ALL* paths break)
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()
  
    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]
  
      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break
    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2
  
      # If we have learned a MAC on this port which we now know to
      # be connected to a switch, unlearn it.
      bad_macs = set()
      for mac,(sw,port) in mac_map.iteritems():
        #print sw,sw1,port,l.port1
        if sw is sw1 and port == l.port1:
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
        if sw is sw2 and port == l.port2:
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
      for mac in bad_macs:
        del mac_map[mac]
  
  def _handle_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      # New switch
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)
  
  def _handle_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      #log.info("No waiting packet %s,%s", event.dpid, event.xid)
      return
    #log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
    wp.notify(event)
  
  
def launch ():
  core.registerNew(l2_multi)
  
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)
  print 'Timer for Flow statistics'
  #Timer(5, Switch().flow_stat, recurring = True)
  core.openflow.addListenerByName("FlowStatsReceived",
  Switch()._handle_flowstats_received)
