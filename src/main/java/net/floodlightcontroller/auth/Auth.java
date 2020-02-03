package net.floodlightcontroller.auth;

import java.util.*;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.IPv4;
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
import org.sdnplatform.sync.internal.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Auth implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected static Logger logger;
    protected TraceCollector tc;

    protected Map<Pair<IOFSwitch, IPv4Address>, OFPort> table;
    protected Set<IPv4Address> auth;
    protected static final Set<IPv4Address> AUTH_SERVERS = new HashSet<>(Arrays.asList(IPv4Address.of("10.0.0.4")));
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
        return "auth";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // no prereq
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
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
        logger = LoggerFactory.getLogger(Auth.class);
        table = new HashMap<Pair<IOFSwitch, IPv4Address>, OFPort>();
        auth = new HashSet<IPv4Address>();
        auth.addAll(AUTH_SERVERS);
        tc = new TraceCollector("auth");
        if (logger.isTraceEnabled()) {
            logger.debug("module auth initialized");
        }
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        // always place in pipeline at bootup
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
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));

        if (eth.getEtherType() != Ethernet.TYPE_IPv4) {
            return Command.CONTINUE;
        }

        tc.addTableNames("table", "auth");
        tc.addInput(pi, sw, cntx, table, auth);

        IPv4 ip = (IPv4) eth.getPayload();
        IPv4Address srcIp = ip.getSourceAddress();
        IPv4Address dstIp = ip.getDestinationAddress();

        //learn the source
        table.put(new Pair<IOFSwitch, IPv4Address>(sw, srcIp), inPort);
        OFPort outPort = table.get(new Pair<IOFSwitch, IPv4Address>(sw, dstIp));

        if (AUTH_SERVERS.contains(srcIp)) {
            auth.add(dstIp);
            logger.trace("{} is authorized", new Object[]{dstIp});
        }

        if (outPort == null) {
            if (AUTH_SERVERS.contains(dstIp)) {
                OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

                List<OFAction> actions = new ArrayList<OFAction>();
                if (sw.hasAttribute(IOFSwitch.PROP_SUPPORTS_OFPP_FLOOD)) {
                    actions.add(sw.getOFFactory().actions().output(OFPort.FLOOD, Integer.MAX_VALUE)); // FLOOD is a more selective/efficient version of ALL
                } else {
                    actions.add(sw.getOFFactory().actions().output(OFPort.ALL, Integer.MAX_VALUE));
                }
                pob.setActions(actions);

                pob.setBufferId(OFBufferId.NO_BUFFER);
                pob.setInPort(inPort);
                pob.setData(pi.getData());
                sw.write(pob.build());

                //tc.addOutput(pob.build());
            }
        }
        else {
            if (auth.contains(srcIp) && auth.contains(dstIp)) {
                OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();

                Match.Builder mb = sw.getOFFactory().buildMatch();
                mb.setExact(MatchField.IPV4_SRC, srcIp)
                        .setExact(MatchField.IPV4_DST, dstIp)
                        .setExact(MatchField.ETH_TYPE, EthType.IPv4);

                List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));

                U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
                fmb.setMatch(mb.build()) // was match w/o modifying input port
                        .setActions(actions)
                        .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                        .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                        .setBufferId(OFBufferId.NO_BUFFER)
                        .setCookie(cookie)
                        .setOutPort(outPort)
                        .setPriority(FLOWMOD_DEFAULT_PRIORITY);
                if (logger.isTraceEnabled()) {
                    logger.trace("Auth:Installing {} -> {}", new Object[]{srcIp, dstIp});
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
            } else if (AUTH_SERVERS.contains(dstIp)) {
                OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

                List<OFAction> actions = new ArrayList<OFAction>();
                actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
                pob.setActions(actions);
                pob.setBufferId(OFBufferId.NO_BUFFER);
                pob.setInPort(inPort);
                pob.setData(pi.getData());
                sw.write(pob.build());

                //tc.addOutput(pob.build());
            }
        }
        tc.addFinalStates(table, auth);

        return Command.CONTINUE;
    }
}




