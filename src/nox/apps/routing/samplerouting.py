from nox.lib import core
from nox.lib.core import Component
from nox.lib import openflow
from nox.lib.netinet import netinet
from nox.lib.packet.ethernet import ethernet
from nox.apps.pyrt.pycomponent import CONTINUE
from nox.apps.authenticator.pyflowutil import Flow_in_event

from nox.apps.routing import pyrouting

from socket import ntohs, htons
from twisted.python import log

U32_MAX = 0xffffffff
DP_MASK = 0xffffffffffff
PORT_MASK = 0xffff

BROADCAST_TIMEOUT   = 60
FLOW_TIMEOUT        =  5

# DOESN'T YET NAT UNKNOWN DESTINATION PACKETS THAT ARE FLOODED

class SampleRouting(Component):
    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.routing = None

    def install(self):
        self.routing = self.resolve(pyrouting.PyRouting)
        self.register_handler(Flow_in_event.static_get_name(),
                              self.handle_flow_in)

    def handle_flow_in(self, event):
        if not event.active:
            return CONTINUE
        indatapath = netinet.create_datapathid_from_host(event.datapath_id)
        route = pyrouting.Route()
        sloc = event.route_source
        if sloc == None:
            sloc = event.source['location']
        route.id.src = netinet.create_datapathid_from_host(sloc & DP_MASK)
        inport = (sloc >> 48) & PORT_MASK
        if len(event.route_destinations) > 0:
            dstlist = event.route_destinations
        else:
            dstlist = event.destinations
        checked = False
        for dst in dstlist:
            if isinstance(dst, dict):
                if not dst['allowed']:
                    continue
                dloc = dst['connector']['location']
            else:
                dloc = dst
            if dloc == 0:
                continue
            route.id.dst = netinet.create_datapathid_from_host(dloc & DP_MASK)
            if self.routing.get_route(route):
                checked = True
                outport = (dloc >> 48) & PORT_MASK
                if self.routing.check_route(route, inport, outport):
                    log.msg('Found route %s.' % hex(route.id.src.as_host())+':'+str(inport)+' to '+hex(route.id.dst.as_host())+':'+str(outport))
                    actions = [self.make_action_array([[openflow.OFPAT_SET_DL_SRC, event.flow.dl_src]])]
                    for i in xrange(route.path.size()):
                        actions.append("")
                    self.routing.setup_route(event.flow, route, inport, outport, FLOW_TIMEOUT, actions, True)
                    if indatapath == route.id.src or pyrouting.dp_on_route(indatapath, route):
                        self.routing.send_packet(indatapath, inport, openflow.OFPP_TABLE,
                                                 event.buffer_id, event.buf, "", False, event.flow)
                    else:
                        log.err("Packet not on route - dropping.")
                    return CONTINUE
                else:
                    log.msg("Invalid route between %s." % hex(route.id.src.as_host())+':'+str(inport)+' to '+hex(route.id.dst.as_host())+':'+str(outport))
            else:
                log.msg("No route between %s and %s." % (hex(route.id.src.as_host()), hex(route.id.dst.as_host())))
        if not checked:
            log.msg('Broadcasting packet')

            if event.flow.dl_dst.is_broadcast():
                self.routing.setup_flow(event.flow, indatapath, openflow.OFPP_FLOOD,
                                        event.buffer_id, event.buf, BROADCAST_TIMEOUT,
                                        "", event.flow.dl_type == htons(ethernet.IP_TYPE))
            else:
                inport = ntohs(event.flow.in_port)
                self.routing.send_packet(indatapath, inport, openflow.OFPP_FLOOD,
                                         event.buffer_id, event.buf, "",
                                         event.flow.dl_type == htons(ethernet.IP_TYPE),
                                         event.flow)
        else:
            log.msg("Dropping packet")

        return CONTINUE

    def getInterface(self):
        return str(SampleRouting)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return SampleRouting(ctxt)

    return Factory()
