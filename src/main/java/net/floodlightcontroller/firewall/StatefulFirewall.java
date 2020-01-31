package net.floodlightcontroller.firewall;


import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.tracecollector.TraceCollector;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.IRoutingDecision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatefulFirewall implements IOFMessageListener, IFloodlightModule {

    // service modules needed
    protected IFloodlightProviderService floodlightProvider;
    protected static Logger logger;
    protected Set<MacAddress> trusted;
    protected TraceCollector tc;

    public static int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 1000; // in seconds
    public static int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    public static int FLOWMOD_DEFAULT_PRIORITY = 1; // 0 is the default table-miss flow in OF1.3+, so we need to use 1

    public static final int FORWARDING_APP_ID = 2;
    // by a global APP_ID class
    static {
        AppCookie.registerApp(FORWARDING_APP_ID, "Forwarding");
    }

    @Override
    public String getName() {
        return "statefulfirewall";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // no prereq
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        logger = LoggerFactory.getLogger(StatefulFirewall.class);
        trusted = new ConcurrentSkipListSet<MacAddress>();
        tc = new TraceCollector("statefulfirewall");
        if (logger.isTraceEnabled()) {
            logger.trace("module statefulfirewall initialized");
        }
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        // always place firewall in pipeline at bootup
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                IRoutingDecision decision = null;
                if (cntx != null) {
                    decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
                    return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
                }
                break;
            default:
                break;
        }

        return Command.CONTINUE;
    }


    public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
        tc.addTableNames("trusted");
        tc.addInput(pi, sw, cntx, trusted);

        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));

        if (sw.getId().equals(DatapathId.of(1))) {
            if (eth.getEtherType() == Ethernet.TYPE_ARP) {
                OFPort outPort = (inPort == OFPort.of(2) ? OFPort.of(1) : OFPort.of(2));

                OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
                List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
                pob.setActions(actions);

                pob.setBufferId(OFBufferId.NO_BUFFER);
                pob.setInPort(inPort);
                pob.setData(pi.getData());

                if (logger.isTraceEnabled()) {
                    logger.trace("Firewall:Writing flood PacketOut For ARP packets, switch={} packet-in={} packet-out={}",
                            new Object[]{sw, pi, pob.build()});
                }
                sw.write(pob.build());

                tc.addOutput(pob.build());
            } else if (inPort == OFPort.of(1)) {
                OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
                //Install flow from port 1 to 2
                Match.Builder mb = sw.getOFFactory().buildMatch();
                mb.setExact(MatchField.ETH_SRC, eth.getSourceMACAddress())
                        .setExact(MatchField.ETH_DST, eth.getDestinationMACAddress());

                List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(sw.getOFFactory().actions().output(OFPort.of(2), Integer.MAX_VALUE));

                U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
                fmb.setMatch(mb.build()) // was match w/o modifying input port
                        .setActions(actions)
                        .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                        .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                        .setBufferId(OFBufferId.NO_BUFFER)
                        .setCookie(cookie)
                        .setOutPort(OFPort.of(2))
                        .setPriority(FLOWMOD_DEFAULT_PRIORITY);
                if (logger.isTraceEnabled()) {
                    logger.trace("Firewall:Installing flow from port 1 to 2");
                }
                sw.write(fmb.build());

                tc.addOutput(fmb.build());
                //Push this packet out
                OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
                pob.setActions(actions);
                pob.setBufferId(OFBufferId.NO_BUFFER);
                pob.setInPort(inPort);
                pob.setData(pi.getData());
                sw.write(pob.build());

                tc.addOutput(pob.build());

                trusted.add(eth.getDestinationMACAddress());
            } else if (inPort == OFPort.of(2)) {
                if (trusted.contains(eth.getSourceMACAddress())) {
                    OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
                    //Install flow from port 2 to 1
                    Match.Builder mb = sw.getOFFactory().buildMatch();
                    mb.setExact(MatchField.ETH_SRC, eth.getSourceMACAddress())
                            .setExact(MatchField.ETH_DST, eth.getDestinationMACAddress());

                    List<OFAction> actions = new ArrayList<OFAction>();
                    actions.add(sw.getOFFactory().actions().output(OFPort.of(1), Integer.MAX_VALUE));

                    U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
                    fmb.setMatch(mb.build()) // was match w/o modifying input port
                            .setActions(actions)
                            .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                            .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                            .setBufferId(OFBufferId.NO_BUFFER)
                            .setCookie(cookie)
                            .setOutPort(OFPort.of(1))
                            .setPriority(FLOWMOD_DEFAULT_PRIORITY);
                    if (logger.isTraceEnabled()) {
                        logger.trace("Firewall:Installing flow from port 2 to 1");
                    }
                    sw.write(fmb.build());

                    tc.addOutput(fmb.build());
                    //Push this packet out
                    OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
                    pob.setActions(actions);
                    pob.setBufferId(OFBufferId.NO_BUFFER);
                    pob.setInPort(inPort);
                    pob.setData(pi.getData());
                    sw.write(pob.build());

                    tc.addOutput(fmb.build());
                }
            }
            tc.addFinalStates(trusted);

            return Command.STOP;
        } else {
            /*
            if (logger.isTraceEnabled()) {
                logger.trace("Firewall:Not handling packet from, sw={} inPort={}",
                        new Object[]{sw, inPort});
            }
             */
            tc.addFinalStates(trusted);

            return Command.CONTINUE;
        }
    }

}

