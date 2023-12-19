package edu.brown.cs.sdn.apps.sps;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import edu.brown.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.packet.Ethernet;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.brown.cs.sdn.apps.util.Host;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
	
	// Interface to the logging system
    private static final Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	// control the log for debug
	private static final boolean isLog = false;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			updateRules(host);
			/*****************************************************************/
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		removeRules(host);
		/*********************************************************************/
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		removeRules(host);
		updateRules(host);
		/*********************************************************************/
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param switchId for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		for (Host host : getHosts()) {
			removeRules(host);
			updateRules(host);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param switchId for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		for (Host host : getHosts()) {
			removeRules(host);
			updateRules(host);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		for (Host host : getHosts()) {
			removeRules(host);
			updateRules(host);
		}
		/*********************************************************************/
	}

	/**
	 * this class uses bellman-ford for shortest path in directed graph,
	 * which is implemented under guide of pseudocode
	 * @param srcSwitch default switch that connects to the host
	 * @param links	all links given by getLinks()
	 * @param switches all switches in SDN given by getSwitches()
	 */
	public Map<Long, Integer> getShortestPaths(IOFSwitch srcSwitch, Collection<Link> links, Map<Long, IOFSwitch> switches) {
		int WEIGHT = 1;
		Map<Long, Integer> distTo = new HashMap<Long, Integer>();	// dst -> distance
		Map<Long, Integer> edgeTo = new HashMap<Long, Integer>();	// dst -> predecessor's port

		// init distTo
		for (long sId: switches.keySet()) {
			distTo.put(sId, Integer.MAX_VALUE - 1);		// prevent int overflow
		}
		distTo.put(srcSwitch.getId(), 0);

		for (int v = 0; v < switches.size(); v++) {
			// relax
			for (Link link: links) {
				long src = link.getSrc(), dst = link.getDst();

				// it's a bidirectional graph, so we have to check both direction
				if (distTo.get(dst) > distTo.get(src) + WEIGHT) {
					distTo.put(dst, distTo.get(src) + WEIGHT);
					edgeTo.put(dst, link.getDstPort());
				}

				if (distTo.get(src) > distTo.get(dst) + WEIGHT) {
					distTo.put(src, distTo.get(dst) + WEIGHT);
					edgeTo.put(src, link.getSrcPort());
				}
			}
		}

		return edgeTo;
	}

	/**
	 * Update routing table when changes happen
	 * @param host the host that need to be updated
	 */
	public void updateRules(Host host) {
		if (!host.isAttachedToSwitch() || host.getIPv4Address() == null) {
			if (isLog)
				log.info(String.format("Host %s is not attached or doesnt get IP addr. [in updateRoutingTable()]", host.getName()));
			return ;
		}

		if (isLog)
			log.info(String.format("Host %s, ip: %s, sw: %d, rules begin to updated.", host.getName(), host.getIPv4Address(), host.getSwitch().getId()));

		// get the shortest path using bellman ford
		// and have to connect the host to its default switch by put one entry in map
		Map<Long, Integer> shortestPaths = getShortestPaths(host.getSwitch(), getLinks(), getSwitches());
		shortestPaths.put(host.getSwitch().getId(), host.getPort());

		if (isLog)
			log.info(String.format("Shortest path table for Host %s: %s.", host.getName(), shortestPaths.toString()));

		// set up matches, the dst is the host's ip addr
		OFMatch match = new OFMatch()
				.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, host.getIPv4Address());

		// insert rules for each switch if its id contained in the SPs map.
		for (IOFSwitch sw: getSwitches().values()) {
			if (!shortestPaths.containsKey(sw.getId())) {
				continue;
			}

			if (isLog)
				log.info(String.format("Adding sw %d rule for Host %s...", sw.getId(), host.getName()));

			OFAction action = new OFActionOutput(shortestPaths.get(sw.getId()));
			OFInstruction instruction = new OFInstructionApplyActions(Arrays.asList(action));
			SwitchCommands.installRule(
					sw,
					table,
					SwitchCommands.DEFAULT_PRIORITY,
					match,
					Arrays.asList(instruction)
			);
		}

		if (isLog)
			log.info(String.format("Host %s rules update complete.", host.getName()));
	}

	/**
	 * clear all rules in switches.
	 * @param host the host that need to be updated
	 */
	private void removeRules(Host host) {
		if (!host.isAttachedToSwitch() || host.getIPv4Address() == null) {
			if (isLog)
				log.info(String.format("Host %s is not attached or doesnt get IP addr. [in clearRules()]",
					host.getName()));
			return ;
		}

		// remove rules in all switches with match
		OFMatch match = new OFMatch()
				.setDataLayerType(Ethernet.TYPE_IPv4)
				.setNetworkDestination(OFMatch.ETH_TYPE_IPV4, host.getIPv4Address());

		for (IOFSwitch sw: getSwitches().values()) {
			SwitchCommands.removeRules(sw, table, match);
		}

		if (isLog)
			log.info(String.format("Host %s rules are cleared",
				host.getName()));
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param switchId for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param switchId for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param switchId for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}