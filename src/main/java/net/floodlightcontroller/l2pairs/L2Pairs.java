/**
 *    Copyright 2011, Big Switch Networks, Inc.
 *    Originally created by David Erickson, Stanford University
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/
package net.floodlightcontroller.l2pairs;
/*
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.Ethernet;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.sdnplatform.sync.internal.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class L2Pairs implements IOFMessageListener, IFloodlightModule {

    protected static Logger log = LoggerFactory.getLogger(L2Pairs.class);

    public static int FLOWMOD_DEFAULT_IDLE_TIMEOUT = 5; // in seconds
    public static int FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    public static int FLOWMOD_DEFAULT_PRIORITY = 1; // 0 is the default table-miss flow in OF1.3+, so we need to use 1
    // flow-mod - for use in the cookie
    public static final int FORWARDING_APP_ID = 2;
    // by a global APP_ID class
    static {
        AppCookie.registerApp(FORWARDING_APP_ID, "L2_Pairs");
    }

    protected IFloodlightProviderService floodlightProviderService;
    protected Map<Pair<IOFSwitch, MacAddress>, OFPort> macToPortMap;

    protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        // Set Action to flood
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
        List<OFAction> actions = new ArrayList<OFAction>();
        if (sw.hasAttribute(IOFSwitch.PROP_SUPPORTS_OFPP_FLOOD)) {
            actions.add(sw.getOFFactory().actions().output(OFPort.FLOOD, Integer.MAX_VALUE)); // FLOOD is a more selective/efficient version of ALL
        } else {
            actions.add(sw.getOFFactory().actions().output(OFPort.ALL, Integer.MAX_VALUE));
        }
        pob.setActions(actions);
        // set buffer-id, in-port and packet-data based on packet-in
        pob.setBufferId(OFBufferId.NO_BUFFER);
        pob.setInPort(inPort);
        pob.setData(pi.getData());

        if (log.isTraceEnabled()) {
            log.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
                    new Object[] {sw, pi, pob.build()});
        }
        sw.write(pob.build());
        return;
    }

    protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        MacAddress srcMac = eth.getSourceMACAddress();
        MacAddress dstMac = eth.getDestinationMACAddress();
        Pair<IOFSwitch, MacAddress> lookup = new Pair<IOFSwitch, MacAddress>(sw, dstMac);

        OFFlowMod.Builder fmb;
        fmb = sw.getOFFactory().buildFlowAdd();
        //flow in
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_SRC, dstMac)
                .setExact(MatchField.ETH_DST, srcMac);

        OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
        List<OFAction> actions = new ArrayList<OFAction>();
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        OFPort outPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        aob.setPort(outPort);
        aob.setMaxLen(Integer.MAX_VALUE);
        actions.add(aob.build());

        U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
        fmb.setMatch(mb.build()) // was match w/o modifying input port
                .setActions(actions)
                .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                .setBufferId(OFBufferId.NO_BUFFER)
                .setCookie(cookie)
                .setOutPort(outPort)
                .setPriority(FLOWMOD_DEFAULT_PRIORITY);
        if (log.isTraceEnabled()) {
            log.trace("Pushing flowmod sw={} inPort={} outPort={}",
                    new Object[] {sw, inPort, outPort});
        }
        sw.write(fmb.build());
        //flow out
        fmb = sw.getOFFactory().buildFlowAdd();

        mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_SRC, srcMac)
                .setExact(MatchField.ETH_DST, dstMac);

        aob = sw.getOFFactory().actions().buildOutput();
        actions = new ArrayList<OFAction>();
        outPort = macToPortMap.get(lookup);
        aob.setPort(outPort);
        aob.setMaxLen(Integer.MAX_VALUE);
        actions.add(aob.build());

        if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
            log.error("No BufferId!!!");
        }
        else {
            fmb.setMatch(mb.build()) // was match w/o modifying input port
                    .setActions(actions)
                    .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                    .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                    .setBufferId(pi.getBufferId())//set the BufferId instead of doing PacketOut
                    .setCookie(cookie)
                    .setOutPort(outPort)
                    .setPriority(FLOWMOD_DEFAULT_PRIORITY);
        }
        if (log.isTraceEnabled()) {
            log.trace("Pushing flowmod sw={} inPort={} outPort={}",
                    new Object[] {sw, inPort, outPort});
        }
        sw.write(fmb.build());

        return;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        OFPacketIn pi = (OFPacketIn)msg;
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        MacAddress dstMac = eth.getDestinationMACAddress();
        MacAddress srcMac = eth.getSourceMACAddress();

        macToPortMap.put(new Pair<IOFSwitch, MacAddress>(sw, srcMac), inPort);

        if (macToPortMap.get(new Pair<IOFSwitch, MacAddress>(sw, dstMac)) == null) {
            doFlood(sw, pi, cntx);
        }
        else {
            doForwardFlow(sw, pi, cntx);
        }
        return Command.STOP;
    }

    @Override
    public String getName() {
        return "L2_Pairs";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
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
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
        macToPortMap = new ConcurrentHashMap<Pair<IOFSwitch, MacAddress>, OFPort>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
*/


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.debugcounter.IDebugCounterService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.topology.ITopologyService;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.sdnplatform.sync.internal.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class L2Pairs extends ForwardingBase implements IFloodlightModule {
    protected static Logger log = LoggerFactory.getLogger(L2Pairs.class);
    protected Map<Pair<IOFSwitch, MacAddress>, OFPort> macToPortMap;

    @Override
    public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        MacAddress dstMac = eth.getDestinationMACAddress();
        MacAddress srcMac = eth.getSourceMACAddress();

        macToPortMap.put(new Pair<IOFSwitch, MacAddress>(sw, srcMac), inPort);

        if (macToPortMap.get(new Pair<IOFSwitch, MacAddress>(sw, dstMac)) == null) {
            doFlood(sw, pi, cntx);
            if (log.isTraceEnabled()) {
                log.trace("Writing flood");
            }
        }
        else {
            doForwardFlow(sw, pi, cntx);
            if (log.isTraceEnabled()) {
                log.trace("Writing forward");
            }
        }

        return Command.CONTINUE;
    }

    protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        MacAddress srcMac = eth.getSourceMACAddress();
        MacAddress dstMac = eth.getDestinationMACAddress();

        OFFlowMod.Builder fmb;
        fmb = sw.getOFFactory().buildFlowAdd();
        //flow in
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_SRC, dstMac)
                .setExact(MatchField.ETH_DST, srcMac);

        OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
        List<OFAction> actions = new ArrayList<OFAction>();
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        OFPort outPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        aob.setPort(outPort);
        aob.setMaxLen(Integer.MAX_VALUE);
        actions.add(aob.build());

        U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
        fmb.setMatch(mb.build()) // was match w/o modifying input port
                .setActions(actions)
                .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                .setBufferId(OFBufferId.NO_BUFFER)
                .setCookie(cookie)
                .setOutPort(outPort)
                .setPriority(FLOWMOD_DEFAULT_PRIORITY);
        if (log.isTraceEnabled()) {
            log.trace("Pushing flowmod sw={} inPort={} outPort={}",
                    new Object[] {sw, inPort, outPort});
        }
        sw.write(fmb.build());
        //flow out
        fmb = sw.getOFFactory().buildFlowAdd();

        mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_SRC, srcMac)
                .setExact(MatchField.ETH_DST, dstMac);

        aob = sw.getOFFactory().actions().buildOutput();
        actions = new ArrayList<OFAction>();
        outPort = macToPortMap.get(new Pair<IOFSwitch, MacAddress>(sw, dstMac));
        aob.setPort(outPort);
        aob.setMaxLen(Integer.MAX_VALUE);
        actions.add(aob.build());

        if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
            log.error("No BufferId!!!");
        }
        else {
            fmb.setMatch(mb.build()) // was match w/o modifying input port
                    .setActions(actions)
                    .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
                    .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
                    .setBufferId(pi.getBufferId())//set the BufferId instead of doing PacketOut
                    .setCookie(cookie)
                    .setOutPort(outPort)
                    .setPriority(FLOWMOD_DEFAULT_PRIORITY);
        }
        if (log.isTraceEnabled()) {
            log.trace("Pushing flowmod sw={} inPort={} outPort={}",
                    new Object[] {sw, inPort, outPort});
        }
        sw.write(fmb.build());

        return;
    }

    protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        // Set Action to flood
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
        List<OFAction> actions = new ArrayList<OFAction>();
        if (sw.hasAttribute(IOFSwitch.PROP_SUPPORTS_OFPP_FLOOD)) {
            actions.add(sw.getOFFactory().actions().output(OFPort.FLOOD, Integer.MAX_VALUE)); // FLOOD is a more selective/efficient version of ALL
        } else {
            actions.add(sw.getOFFactory().actions().output(OFPort.ALL, Integer.MAX_VALUE));
        }
        pob.setActions(actions);
        // set buffer-id, in-port and packet-data based on packet-in
        pob.setBufferId(OFBufferId.NO_BUFFER);
        pob.setInPort(inPort);
        pob.setData(pi.getData());

        if (log.isTraceEnabled()) {
            log.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
                    new Object[] {sw, pi, pob.build()});
        }
        sw.write(pob.build());
        return;
    }

    // IFloodlightModule methods
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // We don't export any services
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService>
    getServiceImpls() {
        // We don't have any services
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        l.add(IDeviceService.class);
        l.add(IRoutingService.class);
        l.add(ITopologyService.class);
        l.add(IDebugCounterService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        super.init();
        this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceManagerService = context.getServiceImpl(IDeviceService.class);
        this.routingEngineService = context.getServiceImpl(IRoutingService.class);
        this.topologyService = context.getServiceImpl(ITopologyService.class);
        this.debugCounterService = context.getServiceImpl(IDebugCounterService.class);
        this.switchService = context.getServiceImpl(IOFSwitchService.class);
        macToPortMap = new ConcurrentHashMap<Pair<IOFSwitch, MacAddress>, OFPort>();

    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        super.startUp();
    }
}