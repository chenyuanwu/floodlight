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
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.sdnplatform.sync.internal.util.Pair;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


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
        out_port = ((OFActionOutput)msg.getActions().get(0)).getPort().getPortNumber();
    }

    @Override
    public String toTupleString() {
        if (out_port == OFPort.FLOOD.getPortNumber() || out_port == OFPort.ALL.getPortNumber()) {
            return String.format("flood(%d, x%x)", dpid, buffer_id);
        }
        else {
            return String.format("packet_out(%d, x%x, %d)", dpid, buffer_id, out_port);
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
    /*
        For PacketIn messages, The buffer id is a unique value used to track the buffered packet
    */

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
        if (pi.getBufferId() != OFBufferId.NO_BUFFER) {
            buffer_id = pi.getBufferId().getInt();
        } else {
            buffer_id = pi.hashCode();
        }

        eth_src = Convert.convertMac(eth.getSourceMACAddress());
        eth_dst = Convert.convertMac(eth.getDestinationMACAddress());
        eth_type = eth.getEtherType() & 0xffff;

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
            return String.format("packet_in_l3(%d, %d, x%x, %s, %s)", dpid, port, buffer_id, ip_src, ip_dst);
        }
        else {
            return String.format("packet_in(%d, %d, x%x, %s, %s, %d)", dpid, port, buffer_id, eth_src, eth_dst, eth_type);
        }
    }

    public String toTupleString() {
        return this.toTupleString("l2");
    }
}

class IOInstance {
    protected IOFSwitch sw;
    protected PacketIn packet_in;
    protected List<String> table_names;
    protected Map<String, List> prev_states;
    protected List<OutputMessage> out_msgs;
    protected Map<String, List> cur_states;

    public IOInstance() {
        table_names = new ArrayList<String>();
        prev_states = new ConcurrentHashMap<String, List>();
        out_msgs = new ArrayList<OutputMessage>();
        cur_states = new ConcurrentHashMap<String, List>();
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

    public void addTableNames(String...names) {
        Collections.addAll(table_names, names);
    }

    public void addInput(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx, Object...states) {
        this.sw = sw;
        packet_in = new PacketIn(pi, sw, cntx);
        for (int i = 0; i < states.length; i++) {
            prev_states.put(table_names.get(i), handleStates(states[i]));
        }
    }

    public void addOutput(OFMessage msg) {
        if (msg instanceof OFPacketOut) {
            PacketOut pout = new PacketOut((OFPacketOut)msg, sw);
            pout.buffer_id = packet_in.buffer_id;
            out_msgs.add(pout);
        }
        else if (msg instanceof OFFlowMod) {
            if (((OFFlowMod)msg).getMatch().get(MatchField.ETH_TYPE) != null &&
                    ((OFFlowMod)msg).getMatch().get(MatchField.ETH_TYPE).getValue() == Ethernet.TYPE_IPv4) {
                out_msgs.add(new FlowModL3((OFFlowMod)msg, sw));
            }
            else {
                out_msgs.add(new FlowMod((OFFlowMod)msg, sw));
            }
        }
    }

    public void addFinalStates(Object...states) {
        for (int i = 0; i < states.length; i++) {
            cur_states.put(table_names.get(i), handleStates(states[i]));
        }
    }
}

public class TraceCollector {
    protected File file;
    protected String layer;
    protected IOInstance currentInstance;
    protected long start_time;
    //protected Gson gson;

    public TraceCollector(String outfile, String layer) {
        try {
            this.layer = layer;
            file = new File("/home/floodlight/Desktop/floodlight/tmp/" + outfile + ".trace");
            if (file.exists()) {
                file.delete();
                file.createNewFile();
            } else {
                file.createNewFile();
            }

            FileWriter writter = new FileWriter(file, true);
            Date date = new Date();
            writter.write(String.format("// Trace collected %s\n", date.toString()));
            writter.close();

            currentInstance = null;
            //gson = new Gson();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getStateTuple(Object s, String name) {
        if (s instanceof List) {
            List<String> list = (List<String>)s;
            StringBuilder strbd = new StringBuilder(name + "(");
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
            return String.format("%s(%s)", name, s);
        }
    }

    private void dumpInstance(IOInstance instance) {
        try {
            FileWriter writter = new FileWriter(file, true);
            //gson.toJson(instance, writter);

            //Write edbs to file
            List<String> edb = new ArrayList<>();
            List<String> old_states = new ArrayList<>();
            edb.add(instance.packet_in.toTupleString(layer));

            for (Map.Entry<String, List> entry : instance.prev_states.entrySet()) {
                for (int i = 0; i < entry.getValue().size(); i++) {
                    old_states.add(getStateTuple(entry.getValue().get(i), entry.getKey()));
                    edb.add(getStateTuple(entry.getValue().get(i), entry.getKey()));
                }
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
            for (int i = 0; i < instance.out_msgs.size(); i++) {
                idb.add(instance.out_msgs.get(i).toTupleString());
            }

            for (Map.Entry<String, List> entry : instance.cur_states.entrySet()) {
                for (int i = 0; i < entry.getValue().size(); i++) {
                    if (! old_states.contains(getStateTuple(entry.getValue().get(i), entry.getKey())))
                        idb.add("new_" + getStateTuple(entry.getValue().get(i), entry.getKey()));
                }
            }
            writter.write("IDB {\n");
            for (int i = 0; i < idb.size(); i++) {
                if (i != idb.size() - 1) {
                    writter.write(idb.get(i) + ",\n");
                }
                else {
                    writter.write(idb.get(i) + "\n");
                }
            }
            writter.write("}\n");

            //Collection time
            double collection_time = (System.nanoTime() - start_time) / 1000000000.0;
            writter.write(String.format("// [Collection time(s)] %f\n\n", collection_time));

            writter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void addTableNames(String...names) {
        assert currentInstance == null : "A final state is expected.";
        currentInstance = new IOInstance();
        currentInstance.addTableNames(names);
    }

    public void addInput(OFPacketIn pi, IOFSwitch sw, FloodlightContext cntx, Object...states) {
        assert currentInstance != null :
                String.format("Missing previous input for PacketIn %d in Switch %d.", pi.hashCode(), sw.getId().getLong());
        if (start_time == 0L)
            start_time = System.nanoTime();
        currentInstance.addInput(pi, sw, cntx, states);
    }

    public void addOutput(OFMessage msg) {
        assert currentInstance != null : "Missing previous input.";
        currentInstance.addOutput(msg);
    }

    public void addFinalStates(Object...states) {
        assert currentInstance != null : "Missing previous input.";
        currentInstance.addFinalStates(states);
        dumpInstance(currentInstance);
        currentInstance = null;
    }
}
