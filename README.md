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