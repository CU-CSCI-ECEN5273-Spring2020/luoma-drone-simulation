# luoma-drone-simulation
Jake Luoma's Network Systems Spring 2020 Project

## Installation and Running the Simulation
* Install the Mininet VM listed [here](https://github.com/mininet/openflow-tutorial/wiki/Installing-Required-Software)
* Set up the VM as described [here](https://github.com/mininet/openflow-tutorial/wiki/Set-up-Virtual-Machine). I used the instructions at the bottom of the page to set up the VM with a GUI.
* Put my files into the correct folders
  * `drone_route_controller.py` goes in `~/pox/pox/forwarding/`
  * `mininet-host-program.py` and `mininet-mesh-topology.py` go in `~/mininet/mininet`
* Start the controller in its own terminal with the command `~/pox/pox.py log.level –DEBUG misc.full_payload forwarding.drone_route_controller`
* Start `mininet-mesh-topology.py` in a different terminal with `sudo python ~/mininet/mininet/mininet-mesh-topology.py`
* You can now use the mininet command line to do things like removing links or commanding hosts to ping each other (ie. `h1 ping -c3 h2`)
* The swarm is configured to have addresses in the range 192.168.100.xxx.  Anything outside of that is considered to be external to the swarm. A packet sent to an address outside the swarm is routed to the closest switch/host with internet access.  h1 is configured to know an "internet" address `192.168.255.1` and h3 is configured to have "internet" access. If you issue the command `h1 echo 'hello world!' | nc 192.168.255.1 12345` your packet will be sent to "the internet" as confirmed in the controller logs.