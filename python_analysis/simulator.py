"""
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
"""

import subprocess
import time
import os

from argparse import ArgumentParser
from aioquic.quic.configuration import EFMVariants

import json


"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Start of the Initial Part of the Program
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"""

experimentFiles = os.listdir("../configurations/")
possibleConfigs = []

for filename in experimentFiles:

    name = filename.split(".")

    if name[0] + ".json" in experimentFiles and name[0] not in possibleConfigs:
        possibleConfigs.append(name[0]) 

parser = ArgumentParser(description="EFM Testbed Setup")
parser.add_argument('--config', '-c',
                    dest="config",
                    action="store",
                    help="Which experimental config to run",
                    choices=possibleConfigs,
                    required=True)


args = parser.parse_args()


config_name = args.config
config_path = f"../configurations/{config_name}.json"

try: 
    os.mkdir(f"data")
    print("Created data folder.")
except FileExistsError:
    print("data Folder already exists. \n Continue")

database_path = f"data/{config_name}/"
results_path = f"data/{config_name}/results"


mininet_proc = None
server_proc = None

"""
Set up folders for the measurement results.
They will be placed in data/{name_of_config_file}/results/.
If the 'results' folder already exists, iteratively try to create a folder named results1, results2, etc.
"""

try: 
    os.mkdir(f"data/{config_name}")
except FileExistsError:
    print("Folder already exists. \n Continue")

if os.path.exists(results_path):

    iterator = 1 
    while os.path.exists(results_path + str(iterator)):
        iterator += 1
    results_path = results_path + str(iterator)

try: 
    os.mkdir(results_path)
except Exception as e:
    print("No error should happen here.")
    print(e)




"""
Create a bunch of additional folders.
raw: stores the raw measurement files
preprocessed: stores intermediate files after initial preprocessing
plot_preprocessed: stores intermediate files that are processed so that they can be directly plotted
summary_plot: contains the eventual plots
"""

raw_files_folder = os.path.join(results_path,"raw")
preprocessed_folder = os.path.join(results_path, "preprocessed")
plot_preprocessed_folder = os.path.join(results_path, "plot_preprocessed")
summary_plot_folder = os.path.join(results_path, "summary_plot")

try:
    os.mkdir(raw_files_folder)
except FileExistsError:
    print("{} already exists. \n Continue".format(raw_files_folder))

try:
    os.mkdir(preprocessed_folder)
except FileExistsError:
    print("{} already exists. \n Continue".format(preprocessed_folder))

try:
    os.mkdir(plot_preprocessed_folder)
except FileExistsError:
    print("{} already exists. \n Continue".format(plot_preprocessed_folder))

try:
    os.mkdir(summary_plot_folder)
except FileExistsError:
    print("{} already exists. \n Continue".format(summary_plot_folder))


### Load the config
jsonfile = open(config_path)
config = json.load(jsonfile)
jsonfile.close()


"""^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
End of the Initial Part of the Program
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""


"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Several Helper Functions
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"""


def debugOutput(msg):
    print(32*"# # ")
    print(32*"# # ")
    print(msg + 5 * " X {}".format(msg))

def debugSmallOutput(msg):
    print(16*"- - ")
    print(16*"- - ")
    print(msg + 5 * " X {}".format(msg))


def start_mininet():
    """
    Start mininet using the topology defined in custom_mininet_topo.py
    """
    global mininet_proc

    debugOutput("Start MiniNet")
    mininet_proc = subprocess.Popen(
        f"sudo mn --custom custom_mininet_topo.py --topo mytopo", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    print(f"sudo mn --custom custom_mininet_topo.py --topo mytopo")

    while True:
        line = mininet_proc.stderr.readline()
        if not line:
            break
        if line == b'*** Starting CLI:\n':
            break
        print(line)

    print("DONE")



def add_access_to_h1_h2_namespace():
    """
    Use the add_network_namespace.sh script to facilitate accessing the different entities within mininet (essentially creating a network namespace for each host)
    """

    print("Add access to mininet namespaces of h1 and h2.")
    subprocess.Popen(f"sudo bash add_network_namespace.sh", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

def remove_access_to_h1_h2_namespace():
    """
    Remove the facilitated access by deleting the created network namespaces
    """

    print("Remove access to mininet namespaces of h1 and h2.")
    subprocess.Popen(f"sudo bash remove_network_namespace.sh", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)



def remove_virtual_interfaces():
    """
    Cleanup all virtual interfaces so that we have a clean slate
    """

    print("Remove all virtual interfaces")

    try:
        subprocess.run("sudo ip link delete ovs-system")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s1")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s2")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s3")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s1-eth1")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s1-eth2")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s2-eth1")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s2-eth2")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s3-eth1")
    except FileNotFoundError:
        pass

    try:
        subprocess.run("sudo ip link delete s3-eth2")
    except FileNotFoundError:
        pass



"""
Forcefully kill the ebpf program or the server if they should not respond
"""

def hard_kill_ebpf():
    print("Hard kill ebpf")
    kill_command = "sudo kill $(ps aux | grep '[m]onitor_queue_bpf_enqueue_only.py' | awk '{print $2}')"
    print(kill_command)
    subprocess.run(kill_command, shell=True)


def hard_kill_server():
    print("Hard kill server")
    kill_command = "sudo kill $(ps aux | grep '[t]raffic/server.py' | awk '{print $2}')"
    print(kill_command)
    subprocess.run(kill_command, shell=True)





def start_server(efmvariants, server_host, server_port, packets):
    """
    Start an EFM QUIC Server that uses the Datagram mode.
    Note that keying material is hard-coded.
    
    efmvariants: identifier for which EFM variants are to be used
    server_host: on which host to run the server (leveraging the simplified access via netns)
    server_port: on which port the server listens
    packets: how many packets should be transmitted
    """

    global server_proc

    debugSmallOutput("Start Trash Server")

    command_prefix = "sudo ip netns exec mininet_{} ".format(server_host)
    command = f"python3 ../traffic/server.py --packets {packets} --efmvariants {efmvariants} --serverport {server_port} --keypath ../traffic/ssl_key.pem --certpath ../traffic/ssl_cert.pem"

    command = command_prefix + command
    print(command)

    server_proc = subprocess.Popen(command,  shell=True)


def run_flow(efmvariants, src_host, src_port, packets, target_ip, dst_port):
    """
    Start an EFM QUIC Client that uses the Datagram mode and connects to the EFM QUIC Server.

    efmvariants: identifier for which EFM variants are to be used
    target_ip: which IP to connect to
    dst_port: which port to connect to
    src_host: on which host to run the client (leveraging the simplified access via netns)
    src_port: which source port to use
    packets: how many packets should be transmitted
    """

    debugSmallOutput("Run Trash Flow")

    command_prefix = "sudo ip netns exec mininet_{} ".format(src_host)
    command = f"python3 ../traffic/client.py --target {target_ip} --packets {packets} --srcport {src_port} --dstport {dst_port} --efmvariants {efmvariants}"

    command = command_prefix + command
    print(command)

    subprocess.run(command,  shell=True)


def start_h3_server(efmvariants, server_host, server_port, duration):
    """
    Start an EFM QUIC Server that uses regular HTTP3.

    efmvariants: identifier for which EFM variants are to be used
    server_host: on which host to run the server (leveraging the simplified access via netns)
    server_port: on which port the server listens
    duration: additional timeout information to kill the server after a predefined amount of time
    """

    global server_proc

    debugSmallOutput("Start HTTP Server")

    command_prefix = "sudo ip netns exec mininet_{} ".format(server_host)
    command = f"timeout {duration+5} python3 ../traffic/http3_server.py --efmvariants {efmvariants} --host 0.0.0.0 --port {server_port} -k ../traffic/ssl_key.pem -c ../traffic/ssl_cert.pem"

    command = command_prefix + command
    print(command)
    server_proc = subprocess.Popen(command,  shell=True)


def run_http_flow(efmvariants, src_host, src_port, file_size, target_ip, dst_port):
    """
    Start an EFM QUIC Client that uses regular HTTP3 and connects to the EFM QUIC Server 

    efmvariants: identifier for which EFM variants are to be used
    target_ip: which IP to connect to
    dst_port: which port to connect to
    file_name: which file to download (in our case, filenames directly represent file sizes)
    src_host: on which host to run the client (leveraging the simplified access via netns)
    src_port: which source port to use
    """

    debugSmallOutput("Run HTTP Flow")
    
    file_name = file_size + ".file"

    command_prefix = "sudo ip netns exec mininet_{} ".format(src_host)
    command = f"python3 ../traffic/http3_client.py -k --efmvariants {efmvariants} --srcport {src_port} https://{target_ip}:{dst_port}/" + file_name

    command = command_prefix + command
    print(command)

    subprocess.run(command,  shell=True)

def run_queue_monitor(queue_type, output_file_path, host):
    """
    Run the eBPF-based script to monitor the queue status

    queue_type: specify which type of queue should be observed (in our case, it will be NETEM)
    -> depending on the queue type, there are different callbacks to be triggered in the ebpf file
    output_file_path: where to write the output file to
    host: on which host to run the ebpf tool

    #### NOTE: monitor_queue_bpf_enqueue_only.py has been in use with python2
    """

    command_prefix = ""

    if host in ["h1", "h2"]:

        command_prefix = "sudo ip netns exec mininet_{} ".format(host)

    elif host in ["s1", "s2", "s3"]:

        command_prefix = "sudo "

    executionDir = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

    program_path = os.path.join(executionDir, "monitor_queue_bpf_enqueue_only.py")

    options = "" 
    if queue_type == "NETEM":
        options += "-t NETEM"

    command = f" python2 {program_path} {options} > {output_file_path}"

    command = command_prefix + command
    print(command)
    return subprocess.Popen(command, shell=True)


def startPcap(raw_file_path, pcap_name):
    """
    Run tcpdump to capture all network traffic.
    Capture full-size packets and DON'T apply snaplen, because there might be short header frames that are combined with other frames in the same packet (e.g., upon startup) and we would in those cases lose the initial values and thus get a measurement error in the first iteration.
    """

    def runTcpDump(interface, file_path, host, src_ip,dst_ip):
        """
        interface: which interface to capture
        host: on which host to run tcpdump (using the netns access)
        src_ip/dst_ip: additional filtering using source/destination addresses to reduce size of captured file
        file_path: where to write the output
        """

        command_prefix = "sudo ip netns exec mininet_{} ".format(host)
        command = f"sudo tcpdump -i {interface} -w {file_path} \"udp && src {src_ip} && dst {dst_ip}\""

        command = command_prefix + command
        print(command)

        tcpdump = subprocess.Popen(command, shell=True)


    pcap_file_path = os.path.join(raw_file_path, "{}s2-eth1.pcap".format(pcap_name))
    runTcpDump(interface="s2-eth1", file_path=pcap_file_path, host="s2", src_ip="10.0.1.1", dst_ip="10.0.1.2")
    
    pcap_file_path = os.path.join(raw_file_path, "{}s2-eth2.pcap".format(pcap_name))
    runTcpDump(interface="s2-eth2", file_path=pcap_file_path, host="s2", src_ip="10.0.1.2", dst_ip="10.0.1.1")


    """
    FOR PACKET GROUNDTRUTH
    """
    pcap_file_path = os.path.join(raw_file_path, "{}s3-eth2.pcap".format(pcap_name))
    runTcpDump(interface="s3-eth2", file_path=pcap_file_path, host="s3", src_ip="10.0.1.2", dst_ip="10.0.1.1")



def set_static_link_parameters_mininet(link, arguments, host=""):

    """
    Configure link parameters using tc.
    On link s3-eth1, make sure that the packet loss only affects traffic going from the server to the client by appyling an additional filter for this traffic.
    """

    debugSmallOutput("QDISC")
    command_prefix = "sudo ip netns exec mininet_{} ".format(host)

    if link == "s3-eth1":

        print("Configure the nasty link")

        cmd1 = f"tc qdisc add dev {link} root handle 1: prio"
        cmd = command_prefix + cmd1

        print(cmd)

        subprocess.run(cmd, shell=True)

        """
        Only apply this configuration to traffic coming from ip 10.0.1.2 with port 1234
        """
        cmd2 = f"tc filter add dev {link} parent 1: protocol ip prio 2 u32 match ip src 10.0.1.2/32 match ip protocol 17 0xff match ip sport 1234 0xffff flowid 1:1"
        cmd = command_prefix + cmd2

        print(cmd)

        subprocess.run(cmd, shell=True)


        cmd3 = f"tc qdisc add dev {link} parent 1:1 netem {arguments}"
        cmd = command_prefix + cmd3

        print(cmd)

        subprocess.run(cmd, shell=True)

    else:

        print("Configure a normal link")
        cmd = f"tc qdisc add dev {link} parent root netem {arguments}"
        cmd = command_prefix + cmd
        print(cmd)

        subprocess.run(cmd, shell=True)


def simulate(flow_tests, iterations, host_info):
    """ Actually perform the measurements.
    flow_tests: measurement configurations
    iterations: how often to repeat the measurement
    host_info: name-ip mapping of the involved end-hosts
    """

    try:

        for flow_test in flow_tests:

            ### Additionally store the original flow_test description -> flow_test["description"] will be modified during the process for each iteration
            orig_flow_test_description = flow_test["description"]
            for iteration in range(1,iterations+1):
                print("Start iteration {}".format(iteration))
                flow_test["description"] = orig_flow_test_description

                """
                Basic setup of the testbed with some additional cleaning up of old stuff
                """
                remove_virtual_interfaces()
                time.sleep(1)
                
                start_mininet()

                remove_access_to_h1_h2_namespace()
                add_access_to_h1_h2_namespace()
                time.sleep(1)

                for link_config in flow_test["link_configs"]:
                    print(link_config)
                    set_static_link_parameters_mininet(link_config["link"], link_config["netem_args"], host=link_config["link"].split("-")[0].strip("["))


                print("Run the following flow: " + flow_test["description"])


                """
                Based on the parameters set in the configuration file, determine which value to set in the QUIC EFM client/server
                """
                deployed_techniques = 0
                if flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["delay_paper"] and flow_test["measurement_techniques"]["t_rtpl"] and\
                    flow_test["measurement_techniques"]["q_square"] and flow_test["measurement_techniques"]["r_reflection_square"] and\
                    flow_test["measurement_techniques"]["l_loss_event"] and\
                    flow_test["measurement_techniques"]["vec"] and flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["delay_draft"]:

                    deployed_techniques = EFMVariants.ALL_MEASUREMENTS

                elif flow_test["measurement_techniques"]["t_rtpl"] and flow_test["measurement_techniques"]["q_square"] and\
                        flow_test["measurement_techniques"]["r_reflection_square"] and flow_test["measurement_techniques"]["l_loss_event"]:

                    deployed_techniques = EFMVariants.LOSS_MECHANISMS


                    """ These options involving the 'SPIN' prefix have not been tested recently."""
                else:
                    if flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["delay_paper"] and flow_test["measurement_techniques"]["t_rtpl"]:
                        deployed_techniques = EFMVariants.SPIN_DELAY_PAPER_T_BIT_RTPL
                    elif flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["q_square"] and flow_test["measurement_techniques"]["r_reflection_square"]:
                        deployed_techniques = EFMVariants.SPIN_Q_BIT_SQUARE_R_BIT_REFLECTION_SQUARE
                    elif flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["q_square"] and flow_test["measurement_techniques"]["l_loss_event"]:
                        deployed_techniques = EFMVariants.SPIN_Q_BIT_SQUARE_L_BIT_LOSS_EVENT
                    elif flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["vec"]:
                        deployed_techniques = EFMVariants.SPIN_VEC
                    elif flow_test["measurement_techniques"]["spin"] and flow_test["measurement_techniques"]["delay_draft"] and flow_test["measurement_techniques"]["t_rtpl"]:
                        deployed_techniques = EFMVariants.SPIN_DELAY_DRAFT_T_BIT_RTPL

                flow_test["description"] = flow_test["description"] + "-{}".format(iteration) + "+-+{}+-+".format(deployed_techniques)


                """
                Depending on the traffic setting, perform slightly different configurations
                """
                queue_mon = None
                if "synthetic_traffic" in flow_test.keys():

                    queue_mon = run_queue_monitor(queue_type="NETEM", output_file_path=os.path.join(results_path,"raw",flow_test["description"] + "queue_monitor.txt"), host="s2")

                    start_server(efmvariants=deployed_techniques, server_host=flow_test["dst_host"], server_port=flow_test["dst_port"],
                                packets=flow_test["synthetic_traffic"]["packets"])

                    time.sleep(1)

                    startPcap(os.path.join(results_path,"raw"),flow_test["description"])
                    time.sleep(1)
                    run_flow(efmvariants=deployed_techniques,
                            src_host=flow_test["src_host"], src_port=flow_test["src_port"],
                            packets=flow_test["synthetic_traffic"]["packets"],
                            target_ip=host_info["h2"]["ip"],dst_port=flow_test["dst_port"])


                if "http_traffic" in flow_test.keys():
     
                    file_size = flow_test["http_traffic"]["file_size"]

                    set_duration = -1
                    if file_size in ["50k", "500k"]:
                        set_duration = 120
                    elif file_size in ["2M", "10M"]:
                        set_duration = 120
                    elif file_size in ["200M"]:
                        set_duration = 120
                    else:
                        set_duration = 200

                    print("Start H3 download with a file size of ", file_size)

                    queue_mon = run_queue_monitor(queue_type="NETEM", output_file_path=os.path.join(results_path,"raw",flow_test["description"] + "queue_monitor.txt"), host="s2")

                    start_h3_server(efmvariants=deployed_techniques, server_host=flow_test["dst_host"], server_port=flow_test["dst_port"], duration=set_duration)

                    time.sleep(1)

                    startPcap(os.path.join(results_path,"raw"),flow_test["description"])
                    time.sleep(1)
                    run_http_flow(efmvariants=deployed_techniques,
                                src_host=flow_test["src_host"], src_port=flow_test["src_port"],
                                file_size=file_size,
                                target_ip=host_info["h2"]["ip"], dst_port=flow_test["dst_port"])


                if queue_mon == None:
                    raise Exception
                
                else:
                    time.sleep(1)
                    queue_mon.terminate()
                    hard_kill_ebpf()
                    hard_kill_server()
                    
                print("Exit Mininet")
                mininet_proc.communicate(input=b'exit')

                remove_access_to_h1_h2_namespace()
                remove_virtual_interfaces()

        print(f"Finished all test runs")

    finally:
        remove_access_to_h1_h2_namespace()
        remove_virtual_interfaces()



for f in config["experiment"]["flow_tests"]:
    
    simulate([f], config["experiment"]["iterations"], config["hosts"])