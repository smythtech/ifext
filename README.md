# SDN host InterFace EXTension (IFEXT) Kit 

This tool allows an SDN switch to artificially extend the number of physical interfaces linked to a network host.


# Why

Physical testbeds are important for research as they allow experiments to be performed under real-world conditions. It can, however, be difficult to scale physical testbeds as physical equipment is required to do so. While Virtual Machines (VMs) are a great way to add more hosts and traffic generators to a testbed, servers and physical hosts generally have a limited number of network interfaces available to them which limit the possible physical topology configurations. This tool uses an OpenFlow switch to solve this challenge. By mapping switch ports to MAC addresses, each VM or container running on a server can have a dedicated physical port associated with it.

# Requirements
This tool requires the following:

 - Python3
 
The following commands can be used to install the requirements:

	sudo apt-get install python3

This tool requires an SDN capable switch and the ONOS SDN controller. The tool has been tested with ONOS version 1.15.0. This tool utilizes the ONOS REST API and should therefore be compatible with any data plane technologies (OpenFlow, P4, etc.) that is supported by ONOS. 

# Usage

	usage: ifext.py [-h] [-l LOAD_CONFIG] [-u USER] [-v] [--version]

	SDN host InterFace EXTension (IFEXT) Kit. Creates and installs flow rules that allow an SDN switch to act as an extension to a single physical network interface.

	options:
    -h, --help            show this help message and exit
    -l LOAD_CONFIG, --load-config LOAD_CONFIG
                        Config file with port mappings.
    -u USER, --user USER  Username for REST API. You will be prompted for the
                          password.
    -v, --verbose         Show additional output.
    --version             show program's version number and exit


The following is example contents for a configuration file to be used with this tool. It defines the port number to be used as the source port, as well as the port mappings for the individual hosts. The controller address and port number must be set here. The controller name is set here as this tool may support controllers other than ONOS in the future. 

	{
        "controller": "onos",
        "controller-url": "http://127.0.0.1:8181",
        "source-port": 1,
        "port-mappings": {
                "aa:bb:cc:11:11:11": 2,
                "aa:bb:cc:22:22:22": 3,
                "aa:bb:cc:33:33:33": 4,
                "aa:bb:cc:44:44:44": 5,
                "aa:bb:cc:55:55:55": 6,
                "aa:bb:cc:66:66:66": 7
        }
	}

# How it works

IFEXT manages the flow rules required to disperse traffic coming from a source port across multiple different switch ports. This is done based on a port-to-MAC mapping provided by the user. This tool also manages the configuration needed to suppress topology discovery on the switch.

![image](https://smythtech.net/images/github/ifext_diagram.png)

The physical topology above, paired with the configuration provided in the "usage" section would result in the logical topology shown below:

![image](https://smythtech.net/images/github/ifext_diagram_onos_topo.png)

# Todo

Planned tasks:
 - Allow LLDP and BDDP to flow through switch to hosts.
 - Add support for more controllers.

# Author
Dylan Smyth
