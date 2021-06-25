"""
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
"""

import analyzer_loss   
import os
import subprocess
from argparse import ArgumentParser

parser = ArgumentParser(description="Analysis Tool")
parser.add_argument('--path', '-p',
                    dest="path",
                    action="store",
                    help="Where are the measurement results",
                    required=True)
parser.add_argument('--force', '-f',
                    dest="force",
                    action="store",
                    help="Force analysis of already analyzed files",
                    default=False)
args = parser.parse_args()




def trigger_go_analysis(src_file_path, dst_file_path):
    """ Analyze the .pcap files generated in the experiments as well as the queueMonitor files using analysis logic written in Go."""

    print("Start go-utility-based analysis")

    ### First check which files are there for analysis
    all_result_files = os.listdir(src_file_path)
    prefixSet = set()
    for filename in all_result_files:

        if filename.count('+-+') == 2:

            prefix = "+-+".join(filename.split('+-+')[:2])
            prefixSet.add(prefix)


    ### Analyze the different files in a 'measurement by measurement' manner
    for prefix in prefixSet:

        measurement_technique = prefix.split("+-+")[1]

        print("Check if required .pcap files are present.")
        ### EFM Observer
        pcap1 = os.path.join(src_file_path, prefix + "+-+s2-eth1.pcap")
        pcap2 = os.path.join(src_file_path, prefix + "+-+s2-eth2.pcap")

        ### Groundtruth
        pcap3 = os.path.join(src_file_path, prefix + "+-+s3-eth2.pcap")
        queue_monitor = os.path.join(src_file_path,prefix + "+-+queue_monitor.txt")

        prefix += "+-+"
        
        if pcap1.split("/")[-1] in all_result_files and pcap2.split("/")[-1] in all_result_files:
            print("../go_analysis/am-pcap-analyzer --s2_eth1_pcapFile {pcap1} --s2_eth2_pcapFile {pcap2} --outputFileBaseName {result_file} --measurement_techniques {measurement_techniques}".format(pcap1=os.path.abspath(pcap1),
                                                                                                                                                                                        pcap2=os.path.abspath(pcap2),
                                                                                                                                                                                        result_file=os.path.join(dst_file_path,prefix),
                                                                                                                                                                                        measurement_techniques=measurement_technique))
            subprocess.run("../go_analysis/am-pcap-analyzer --s2_eth1_pcapFile {pcap1} --s2_eth2_pcapFile {pcap2} --outputFileBaseName {result_file} --measurement_techniques {measurement_techniques}".format(pcap1=os.path.abspath(pcap1),
                                                                                                                                                                                        pcap2=os.path.abspath(pcap2),
                                                                                                                                                                                        result_file=os.path.join(dst_file_path,prefix),
                                                                                                                                                                                        measurement_techniques=measurement_technique), shell=True)

        if queue_monitor.split("/")[-1] in all_result_files:

            command= "../go_analysis/analyse_queueMonitor --queueMonitorFileName {queuemonitorfile} --s3_eth2_pcapFile {s3_eth2_pcap} --outputFileBaseName {result_file}".format(queuemonitorfile=os.path.abspath(queue_monitor), 
                                                                                                                                                                                s3_eth2_pcap=os.path.abspath(pcap3), 
                                                                                                                                                                                result_file=os.path.join(dst_file_path,prefix))
            subprocess.run(command, shell=True)
        



#generalpath = "/opt/kunze/in-network-troubleshooting/python_analysis/data/paper_eval_congestion"
generalpath = args.path

raw_files_path = os.path.join(generalpath, "raw")
preprocessed_folder = os.path.join(generalpath, "preprocessed")
try: 
    os.mkdir(preprocessed_folder)
except FileExistsError:
    print("Preprocessed already exists :)")
plot_preprocessed_folder = os.path.join(generalpath, "plot_preprocessed")
try: 
    os.mkdir(plot_preprocessed_folder)
except FileExistsError:
    print("Plot_preprocessed already exists :)")





print(30 * "---")
print(30 * "---")
print("Start Go Analysis for Folder {}".format(raw_files_path))
print("First, create destination folder in {}".format(preprocessed_folder))

destinationExists = False
try: 
    os.mkdir(preprocessed_folder)
except FileExistsError:
    print("Destination Folder already exists. Seems that the analysis has already run.")
    destinationExists = True

print("Trigger Go Analysis!")
trigger_go_analysis(raw_files_path, preprocessed_folder)




print(30 * "---")
print(30 * "---")
print("Do the plotting computations.")

analyzer_loss.analyze_loss_scenarios(preprocessed_folder, plot_preprocessed_folder)
