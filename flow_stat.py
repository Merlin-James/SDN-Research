# standard includes
from pox.core import core
from pox.lib.util import dpidToStr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *

# include as part of the betta branch
from pox.openflow.of_json import *

log = core.getLogger()

# handler for timer function that sends the requests to all the
# switches connected to the controller.
def _timer_func ():
  for connection in core.openflow._connections.values():
    connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
  log.debug("Sent %i flow/port stats request(s)", len(core.openflow._connections))

# handler to display flow statistics received in JSON format
# structure of event.stats is defined by ofp_flow_stats()
def _handle_flowstats_received (event):
  stats = flow_stats_to_list(event.stats)
  log.info("flow statistics received from %s",dpidToStr(event.connection.dpid))
  flowlist = {}
  flow_count = 0
  p_count = 0
  b_count = 0
  for flow in event.stats:
    if flow.match.dl_type==0x0800:
      flowlist = {"flow_Duration": flow.duration_sec, "packet_count": flow.packet_count, "byte_count": flow.byte_count}
      p_count += flow.packet_count
      b_count += flow.byte_count
      if flow.packet_count <> 0: 
          flow_count = flow_count+1
  print "Traffic from %s: %s bytes,%s packets and flows  ",dpidToStr(event.connection.dpid), p_count, b_count, flow_count
      #print flow_count
     
def flow_stat():
  self._timer_func()

# main functiont to launch the module
def launch ():
  from pox.lib.recoco import Timer

  # attach handsers to listners
  core.openflow.addListenerByName("FlowStatsReceived",
    _handle_flowstats_received)

  # timer set to execute every five seconds
  Timer(5, _timer_func, recurring=True)

                                                                 

