# Member 1 handoff: Mininet topology + TCP traffic

## Network
- Switch: s1 (Open vSwitch, OpenFlow 1.3, fail_mode secure)
- Hosts: h1=10.0.0.1 (TCP server), h2=10.0.0.2, h3=10.0.0.3, h4=10.0.0.4
- Controller expected at 127.0.0.1:6653 (remote controller, OpenFlow 1.3)
- TCP server: h1, port 5000, replies "HELLO from TCP server" and closes

## Traffic roles
- h2 and h3: normal, 1 TCP connection/second (about 10 per 10 s)
- h4: abnormal, default 5 connections/second (about 50 per 10 s)
- Example threshold: 20 connections per 10 s (experimental, configurable)

## Files
- topology/topology.py : builds the network, starts the server, opens the CLI
- traffic/tcp_server.py : TCP server (logs timestamp and source IP)
- traffic/traffic_gen.py : generator (--rate, --duration, --label, --server, --port)
- basectl/run_controller.py : launcher for OS-Ken apps (the pip package has no osken-manager)
- basectl/learning_switch.py : base controller (forwarding only, no detection or blocking)
- logs/ : server.log and per-host traffic logs (cleared on every start)

## How to run (two terminals)
Terminal 1 (controller):

    cd ~/dhbs && source venv/bin/activate
    python basectl/run_controller.py ~/dhbs/basectl/learning_switch.py

Terminal 2 (network):

    sudo python3 ~/dhbs/topology/topology.py

Commands at the mininet> prompt:

    normal [seconds]            h2 and h3 send normal traffic
    abnormal [rate] [seconds]   h4 sends high-rate traffic
    results                     traffic log summaries and server counts per source IP
    exit

Run "sudo mn -c" if a previous run was killed.

## Notes for the controller member
- To use your own controller, replace learning_switch.py in the controller command.
- The base learning switch installs flows that match MAC addresses only. For per-host
  TCP connection counting you will probably want flows or stats that match IP and TCP fields.
- Blocking should be an OpenFlow DROP rule, so h4 stops reaching h1 while h2 and h3 keep working.

## Setting up a new machine
1. Use Ubuntu 24.04 (a VM is fine; Mininet and OVS only run on Linux).
2. Extract the bundle in your home folder so you get ~/dhbs : tar xzf dhbs_member1.tar.gz -C ~
3. Run: ~/dhbs/setup_env.sh   (installs Mininet, OVS, tools and OS-Ken in ~/dhbs/venv)
4. Follow "How to run" above.
Note: OS-Ken 4.2.2 from pip has no osken-manager launcher, so always start controllers with basectl/run_controller.py.
