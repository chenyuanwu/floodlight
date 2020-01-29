package net.floodlightcontroller.tracecollector;

//import com.google.gson.Gson;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.sdnplatform.sync.internal.util.Pair;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;


class Convert {
    public static String convertMac(MacAddress mac) {
        String s = "x" + mac.toString();
        return s.replace(":", "");
    }

    public static String convertIP(IPv4Address ip) {
        String s = "i" + ip.toString();
        return s.replace(".", "_");
    }
}

interface OutputMessage {
    String toTupleString();
}

class PacketOut implements OutputMessage{
    protected int dpid;
    protected int buffer_id;
    protected int out_port;

    public PacketOut(OFPacketOut msg, IOFSwitch sw) {
        dpid = (int)sw.getId().getLong();
        buffer_id = msg.getBufferId().getInt();
        out_port = ((OFActionOutput)msg.getActions().get(0)).getPort().getPortNumber();
    }

    @Override
    public String toTupleString() {
        if (out_port == OFPort.FLOOD.getPortNumber() || out_port == OFPort.ALL.getPortNumber()) {
            return String.format("flood(%d, %d)", dpid, buffer_id);
        }
        else {
            return String.format("packet_out(%d, %d, %d)", dpid, buffer_id, out_port);
        }
    }
}

class FlowMod implements OutputMessage{
    protected int dpid;
    protected String dl_src;
    protected String dl_dst;
    protected int out_port;

    public FlowMod(OFFlowMod msg, IOFSwitch sw) {
        dpid = (int)sw.getId().getLong();
        dl_src = Convert.convertMac(msg.getMatch().get(MatchField.ETH_SRC));
        dl_dst = Convert.convertMac(msg.getMatch().get(MatchField.ETH_DST));
        if (msg.getActions().size() > 0) {
            out_port = ((OFActionOutput)msg.getActions().get(0)).getPort().getPortNumber();
        }
        else {
            out_port = -1;
        }
    }

    @Override
    public String toTupleString() {
        if (out_port != -1) {
            return String.format("flow_mod(%d, %s, %s, %d)", dpid, dl_src, dl_dst, out_port);
        }
        else {
            return String.format("drop(%d, %s, %s)", dpid, dl_src, dl_dst);
        }
    }
}

class FlowModL3 implements OutputMessage {
    protected int dpid;
    protected String nw_src;
    protected String nw_dst;
    protected int out_port;

    public FlowModL3(OFFlowMod msg, IOFSwitch sw) {
        dpid = (int)sw.getId().getLong();
        nw_src = Convert.convertIP(msg.getMatch().get(MatchField.IPV4_SRC));
        nw_dst = Convert.convertIP(msg.getMatch().get(MatchField.IPV4_DST));
        if (msg.getActions().size() > 0) {
            out_port = ((OFActionOutput)msg.getActions().get(0)).getPort().getPortNumber();
        }
        else {
            out_port = -1;
        }
    }

    @Override
    public String toTupleString() {
        if (out_port != -1) {
            return String.format("flow_mod_l3(%d, %s, %s, %d)", dpid, nw_src, nw_dst, out_port);
        }
        else {
            return String.format("drop_l3(%d, %s, %s)", dpid, nw_src, nw_dst);
        }
    }
}

class PacketIn {
    //Switch information
    protected int dpid;
    protected int port;
    protected int buffer_id;
    //L2 information
    protected String eth_src;
    protected String eth_dst;
    protected int eth_type;
    //L3 information
    protected String ip_src;
    protected String ip_dst;

    public PacketIn(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
        dpid = (int)sw.getId().getLong();
        port = inPort.getPortNumber();
        buffer_id = pi.getBufferId().getInt();

        eth_src = Convert.convertMac(eth.getSourceMACAddress());
        eth_dst = Convert.convertMac(eth.getDestinationMACAddress());
        eth_type = eth.getEtherType();

        if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
            IPv4 ip = (IPv4) eth.getPayload();
            ip_src = Convert.convertIP(ip.getSourceAddress());
            ip_dst = Convert.convertIP(ip.getDestinationAddress());
        }
        else {
            ip_src = null;
            ip_dst = null;
        }
    }

    public String toTupleString(String layer) {
        if (this.eth_type == Ethernet.TYPE_IPv4 && layer.equals("l3")) {
            return String.format("packet_in_l3(%d, %d, %d, %s, %s)", dpid, port, buffer_id, ip_src, ip_dst);
        }
        else {
            return String.format("packet_in(%d, %d, %d, %s, %s, %x)", dpid, port, buffer_id, eth_src, eth_dst, eth_type);
        }
    }

    public String toTupleString() {
        return this.toTupleString("l2");
    }
}

class IOInstance {
    protected IOFSwitch sw;
    protected PacketIn packet_in;
    protected List prev_states;
    protected List<OutputMessage> out_msgs;
    protected List cur_states;

    public IOInstance() {
        sw = null;
        packet_in = null;
        prev_states = new ArrayList();
        out_msgs = new ArrayList<OutputMessage>();
        cur_states = new ArrayList();
    }

    private static String convertStateType(Object k) {
        if (k instanceof IOFSwitch) {
            return String.format("%d", ((IOFSwitch)k).getId().getLong());
        }
        else if (k instanceof MacAddress) {
            return Convert.convertMac((MacAddress)k);
        }
        else if (k instanceof IPv4Address) {
            return Convert.convertIP((IPv4Address)k);
        }
        else if (k instanceof OFPort) {
            return String.format("%d", ((OFPort)k).getPortNumber());
        }
        else {
            return k.toString();
        }
    }

    private static List handleStates(Object states) {
        if (states instanceof Map) {
            //Flatten it here
            List<List<String>> flattened_states = new ArrayList<>();
            for (Map.Entry<?, ?> entry: ((Map<?, ?>)states).entrySet()) {
                List<String> item = new ArrayList<>();
                if (entry.getKey() instanceof Pair) {
                    item.add(convertStateType(((Pair) entry.getKey()).getFirst()));
                    item.add(convertStateType(((Pair) entry.getKey()).getSecond()));
                }
                item.add(convertStateType(entry.getValue()));
                flattened_states.add(item);
            }
            return flattened_states;
        }
        else if (states instanceof Set) {
            List<String> flattened_states = new ArrayList<>();
            for (Object item: (Set)states) {
                flattened_states.add(convertStateType(item));
            }
            return flattened_states;
        }
        else {
            return new ArrayList<>();
        }
    }

    public void addInput(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx, Object states) {
        this.sw = sw;
        packet_in = new PacketIn(pi, sw, cntx);
        prev_states.addAll(handleStates(states));
    }

    public void addInput(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx) {
        this.sw = sw;
        packet_in = new PacketIn(pi, sw, cntx);
    }

    public void addOutput(OFMessage msg) {
        if (msg instanceof OFPacketOut) {
            out_msgs.add(new PacketOut((OFPacketOut)msg, sw));
        }
        else if (msg instanceof OFFlowMod) {
            if (((OFFlowMod)msg).getMatch().get(MatchField.ETH_TYPE).getValue() == Ethernet.TYPE_IPv4) {
                out_msgs.add(new FlowModL3((OFFlowMod)msg, sw));
            }
            else {
                out_msgs.add(new FlowMod((OFFlowMod)msg, sw));
            }
        }
    }

    public void addFinalStates(Object states) {
        cur_states.addAll(handleStates(states));
    }
}

public class TraceCollector {
    protected File file;
    protected IOInstance currentInstance;
    //protected Gson gson;

    public TraceCollector(String outfile) {
        try {
            file = new File("/home/floodlight/Desktop/floodlight/traces/" + outfile + ".trace");
            if (file.exists()) {
                file.delete();
                file.createNewFile();
            } else {
                file.createNewFile();
            }
            currentInstance = null;
            //gson = new Gson();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getStateTuple(Object s) {
        if (s instanceof List) {
            List<String> list = (List<String>)s;
            StringBuilder strbd = new StringBuilder("state(");
            for (int i = 0; i < list.size(); i++) {
                if (i != list.size() - 1) {
                    strbd.append(list.get(i)).append(",");
                }
                else {
                    strbd.append(list.get(i)).append(")");
                }
            }
            return strbd.toString();
        }
        else {
            return String.format("state(%s)", s);
        }
    }

    private void dumpInstance() {
        try {
            FileWriter writter = new FileWriter(file, true);
            //gson.toJson(instance, writter);

            //Write edbs to file
            List<String> edb = new ArrayList<>();
            List<String> old_states = new ArrayList<>();
            edb.add(currentInstance.packet_in.toTupleString("l2"));

            for (int i = 0; i < currentInstance.prev_states.size(); i++) {
                old_states.add(getStateTuple(currentInstance.prev_states.get(i)));
                edb.add(getStateTuple(currentInstance.prev_states.get(i)));
            }
            writter.write("EDB {\n");
            for (int i = 0; i < edb.size(); i++) {
                if (i != edb.size() - 1) {
                    writter.write(edb.get(i) + ",\n");
                }
                else {
                    writter.write(edb.get(i) + "\n}\n");
                }
            }

            //Write idbs to file
            List<String> idb = new ArrayList<>();
            for (int i = 0; i < currentInstance.out_msgs.size(); i++) {
                idb.add(currentInstance.out_msgs.get(i).toTupleString());
            }

            for (int i = 0; i < currentInstance.cur_states.size(); i++) {
                if (! old_states.contains(getStateTuple(currentInstance.cur_states.get(i)))) {
                    idb.add("new_" + getStateTuple(currentInstance.cur_states.get(i)));
                }
            }
            writter.write("IDB {\n");
            for (int i = 0; i < idb.size(); i++) {
                if (i != idb.size() - 1) {
                    writter.write(idb.get(i) + ",\n");
                }
                else {
                    writter.write(idb.get(i) + "\n}\n");
                }
            }

            writter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void addInput(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx, Object states) {
        currentInstance = new IOInstance();
        currentInstance.addInput(pi, sw, cntx, states);
    }

    public void addInput(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx) {
        currentInstance = new IOInstance();
        currentInstance.addInput(pi, sw, cntx);
    }

    public void addOutput(OFMessage msg) {
        currentInstance.addOutput(msg);
    }

    public void addFinalStates(Object states) {
        currentInstance.addFinalStates(states);
        dumpInstance();
        currentInstance = null;
    }

    public void addFinalStates() {
        dumpInstance();
        currentInstance = null;
    }
}
