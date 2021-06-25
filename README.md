# EFM Testbed

## Directory Structure
```
├── configurations -- Measurement configurations
├── go_analysis -- Post-facto analysis scripts written in Go (Observer Logic)
├── python_analysis -- Testbed orchestration software
└── traffic -- Quic client/server code for traffic generation
```

## Publication
This work has been created in the context of the following publication:

* Ike Kunze, Klaus Wehrle, and Jan Rüth: *L, Q, R, and T - Which Spin Bit Cousin Is Here to Stay?*. In ANRW '21: Proceedings of the Applied Networking Research Workshop

If you use any portion of our work, please consider citing our publication.

```
    @Inproceedings{2021-kunze-efm-evaluation,
    author = {Kunze, Ike and Wehrle, Klaus and R{\"u}th, Jan},
    title = {L, Q, R, and T - Which Spin Bit Cousin Is Here to Stay?},
    booktitle = {ANRW '21: Proceedings of the Applied Networking Research Workshop},
    year = {2021},
    month = {July},
    doi = {10.1145/3472305.3472319}
    }
```

## General Remarks
This testbed is designed for use on a Linux system and has only been tested for Ubuntu 18.04.

## Installation
- Install aioquic (see: https://github.com/COMSYS/aioquic)
    - sudo apt install libssl-dev python3-dev
    - git clone git@github.com:COMSYS/aioquic.git / git clone https://github.com/COMSYS/aioquic.git
    - cd aioquic/ && sudo pip install -e . (make sure that pip links to pip3)

- Further setup for the EFM measurement framework
    - sudo apt install mininet
    - Install BCC (https://github.com/iovisor/bcc)
        - sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
    - NOTE: monitor_queue_bpf_enqueue_only.py has been in use with python2

- Install analysis scripts
    - Install libpcap: `sudo apt-get install libpcap-dev`
    - Install golang: `sudo snap install go`
    - Build the different analysis scripts
        - `cd /path/to/efm-evaluation-anrw/go_analysis/ && go build am-pcap-analyzer.go && cd -`
        - `cd /path/to/efm-evaluation-anrw/go_analysis/ && go build analyse_queueMonitor.go && cd -`
        - `cd /path/to/efm-evaluation-anrw/go_analysis/ && go build queueMonitor_burstsize_calculator.go && cd -`
            - This is an additional tool that can be used to determine the burst sizes

- Files for download volumes
    - If you plan to use the H3 mode, please place the corresponding files in traffic/htdocs/
    - Name them like `50k!lossrandom-1`.file where the first part is the experiment description in the configuration file

## Quick Start

- Run a measurement
    - After these steps, you should be able to run a simple example using
    - `cd /path/to/framework/python_analysis/ && python3 simulator.py --config paper_demo`

- Run an analysis
    - `python3 perform_analysis.py --path data/paper_demo/results/`
    - Note: this requires that the go-based analysis scripts have been built


## Experiment Workflow

1. Create an experiment `EXPERIMENT_ID.json` configuration file in `configurations`
    - The analysis framework is currently designed to support analyses for loss occurring on `link s3-eth1`
2. Start the experiment using `python3 simulator.py --config EXPERIMENT_ID.json`
3. The analysis is then performed afterwards
    - `python3 perform_analysis.py --path /path/to/measurements/`



## Content Details

### configurations
There are three configurations used for the evaluation (paper_eval_(random|gemodel|congestion).json) as well as one demo configuration (paper_demo.json) that can be used to test the setup.
The configurations contain the following parameters:
- comment: Short description of the overall configuration
- experiment: specification of the actual traffic settings
    - iterations: defines how often each of the given flow_tests will be performed
    - flow_tests: list of experiments to be performed
        - (src|dst)_(host|port): define src/dst hosts/ports. Note that dst_port 1234 is currently hardcoded in the tc-based network setup scripts.
        - description: short id of the experiement that will be prefixed to the measurement output
        - link_configs: configurations of the involved links. "link" specifies the interface, "netem_args" the corresponding netem arguments.
        - (synthetic|http)_traffic: defines the used traffic type
            - http_traffic - file_size: Defines the file that will be downloaded. Make sure that a corresponding file named "{file_size_argument}.file" is stored in traffic/htdocs
            - synthetic_traffic - packets: Define the number of packets that will be transmitted
            - synthetic_traffic - duration: Define the transmission duration
        - measurement_techniques: enable/disable the desired measurement techniques        
- hosts: define the involved end-hosts as well as their ip addresses


### traffic
There are two client/server pairs.
- client.py / server.py: This implementation uses the datagram mode to continously transmit symmetric traffic between client and server
- http3_client.py / http3_server.py: This implementation is a 'standard' http3 connection. It extends the http3 example of aioquic with corresponding calls to initialize the used EFM variants
    - The ssl_key.pem and ssl_cert.pem we use are also taken from aioquic. 

### python_analysis
This directory contains the actual measurement infrastructure
- simulator.py: main script for performing the measurements
- perform_analysis.py: script for analyzing the measurement results
    - analyzer_loss.py: helper file for the analysis
- custom_mininet_topo.py: specifies the underlying mininet topology
- monitor_queue_bpf_enqueue_only.py: bpf script used to observe the queue state
- average_burst_size_calculator.py: can be used to analyze the observed burst sizes
- [add|remove]_network_namespace.sh: scripts to add helper network namespaces for easier access to the virtual hosts

### go_analysis
This directory contains the observer logic implemented in go
- am-pcap-analyzer.go: Observer logic for the EFM techniques focussing on loss
- analyse_queueMonitor.go: Helper analyzer used to derive the groundtruth
- queueMonitor_burstsize_calculator.go: additional tool that can be used to determine the burst sizes
