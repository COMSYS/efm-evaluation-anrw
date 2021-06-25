"""
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
"""

import os
import subprocess
from argparse import ArgumentParser

parser = ArgumentParser(description="Analysis Tool")
parser.add_argument('--path', '-p',
                    dest="path",
                    action="store",
                    help="Where are the measurement results",
                    required=True)
args = parser.parse_args()


def trigger_go_analysis(raw_files_path, preprocessed_folder):

    """ Check with which measurements the things were performed and then do the analysis """

    print("Start go-utility-based analysis")
    all_result_files = os.listdir(raw_files_path)

    prefixSet = set()
    for filename in all_result_files:

        if filename.count('+-+') == 2:

            prefix = "+-+".join(filename.split('+-+')[:2])
            prefixSet.add(prefix)


    for prefix in prefixSet:

        queue_monitor = os.path.join(raw_files_path,prefix + "+-+queue_monitor.txt")

        prefix += "+-+"
        
        if queue_monitor.split("/")[-1] in all_result_files:

            command= "../go_analysis/queueMonitor_burstsize_calculator --queueMonitorFileName {queuemonitorfile} --outputFileBaseName {result_file}".format(queuemonitorfile=os.path.abspath(queue_monitor), result_file=os.path.join(preprocessed_folder,prefix))

            subprocess.run(command, shell=True)
        

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
destination_folder = os.path.join(preprocessed_folder, "burst_stats")
print("First, create destination folder in {}".format(destination_folder))


try: 
    os.mkdir(destination_folder)
except FileExistsError:
    print("Destination Folder already exists.")

print("Trigger Go Analysis!")
trigger_go_analysis(raw_files_path, destination_folder)
counter += 1


