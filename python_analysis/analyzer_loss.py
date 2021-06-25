"""
    EFM Evaluation Framework
    Copyright (c) 2021 
	
	Author: Ike Kunze
	E-mail: kunze@comsys.rwth-aachen.de
"""

"""
This file provides functionality to analyze the output of the go-based preprocessing and subsequently prepare plottable data.
"""
import os
import datetime
import time


def parseDateTime_withErrorHandling(timestamp):

    def generalHandling(timestamp,timezone="UTC", timezoneoffset="+0000"):

        new_timestamp = ""

        try:
            timestamp = datetime.datetime.strptime(timestamp, f'%Y-%m-%d %H:%M:%S.%f {timezoneoffset} {timezone}')

            return timestamp
        except ValueError:

            print("Original timestamp {} is not well-formed. Try modifying it so that it works.".format(timestamp))
            print("Does not align to format: ", '%Y-%m-%d %H:%M:%S.%f ' + timezoneoffset + " " + timezone)
            coarse_split = timestamp.split("+")
            front_split = coarse_split[0].split(":")
            if "." not in front_split[2]:
                new_timestamp = front_split[0] + ":" + front_split[1] + ":" + front_split[2].strip(" ") + ".000000 " + "+" + coarse_split[1]

        
        try:
            timestamp = datetime.datetime.strptime(new_timestamp, '%Y-%m-%d %H:%M:%S.%f ' + timezoneoffset + " " + timezone)
            print("New format {} works.".format(timestamp))
            return timestamp

        except Exception as e:
            print("Even the new format could not help")
            raise e

    if "CEST" in timestamp:
        timestamp = timestamp.replace("CEST", "UTC")
        timestamp = timestamp.replace("+0200", "+0000")


    return generalHandling(timezone="UTC", timezoneoffset="+0000",timestamp=timestamp)



def compute_loss_ref_gen(generation, reflection):
    """
    Compute loss percentage based on a generation count and a reflection count.
    """

    if generation != 0:
        loss = (1.0 - reflection / generation)*100
    else:
        loss = (1.0 - reflection / (generation+0.1))*100

    return loss if loss >=0 else 0    


def compute_loss_nominal_count(nominal, count):
    """
    Compute loss percentage based on a nominal value and a counted number of packets.
    """

    if nominal != 0:
        loss = (1.0 - count / nominal)*100
    else:
        loss = (1.0 - count / (nominal+0.1))*100

    return loss if loss >=0 else 0  


def compute_loss_packet_count(overall_packets, lost_packets):
    """
    Compute loss percentage based on the number of lost packets and the number of overal packets.
    """

    if overall_packets != 0:
        loss = (lost_packets / overall_packets)*100
    else:
        return 100

    return loss if loss >=0 else 0    


def analyze_tbit(tbit_filename, output=False):
    """
    This function takes pre-processed input from the go-based observers and creates plottable results for the T-Bit. 

    Source format:
    10.0.1.1-10.0.1.2-10000-1234,2021-03-16 16:37:55.983976 +0000 UTC,2021-03-16 16:37:56.370092 +0000 UTC,Generation: 12,Reflection: 13
    """
    if output:
        print("analyze_tbit")

    with open(tbit_filename) as inputFile:

        measurements = {}
        for line in inputFile:

            content = line.split(",")

            src = str(content[0].split("-")[0])

            start_timestamp = content[1]
            end_timestamp = content[2]
            start_timestamp = parseDateTime_withErrorHandling(start_timestamp)
            end_timestamp = parseDateTime_withErrorHandling(end_timestamp)
            
            generation_count = int(content[3].split(":")[1].strip(" "))
            reflection_count = int(content[4].split(":")[1].strip("\n").strip(" "))

            measurements[end_timestamp] = {"direction" : "client_server" if src == "10.0.1.1" else "server_client",
                                            "generation_#": generation_count,
                                            "reflection_#": reflection_count}

        clientserver_last_generation = None
        clientserver_last_reflection = None
        serverclient_last_generation = None
        serverclient_last_reflection = None

        overall_cumulative_generation = 0
        overall_cumulative_reflection = 0
        clientserver_cumulative_generation = 0
        clientserver_cumulative_reflection = 0
        serverclient_cumulative_generation = 0
        serverclient_cumulative_reflection = 0

        clientserver_halfloss_cumulative_generation = 0
        clientserver_halfloss_cumulative_reflection = 0

        serverclient_halfloss_cumulative_generation_phase1 = 0
        serverclient_halfloss_cumulative_reflection_phase1 = 0
        serverclient_halfloss_cumulative_generation_phase2 = 0
        serverclient_halfloss_cumulative_reflection_phase2 = 0

        ## Prepare the return dictionary
        return_dictionary = {   "2dir_observer" : {}, 
                                "cs_observer" : {},
                                "sc_observer" : {},
                                "from_serverclient-observer_to_clientserver-observer" : {},
                                "from_clientserver-observer_to_serverclient-observer" : {}}

        for timestamp in sorted(measurements.keys()):

            generation = measurements[timestamp]["generation_#"]
            overall_cumulative_generation += generation
            reflection = measurements[timestamp]["reflection_#"] 
            overall_cumulative_reflection += reflection

            return_dictionary["2dir_observer"][timestamp] = {
                "loss_percentage": compute_loss_ref_gen(generation, reflection), 
                "generation_#": generation, 
                "reflection_#": reflection, 
                "cum_loss_percentage": compute_loss_ref_gen(overall_cumulative_generation, overall_cumulative_reflection), 
                "cum_generation_#": overall_cumulative_generation, 
                "cum_reflection_#": overall_cumulative_reflection}

            if measurements[timestamp]["direction"] == "client_server":

                clientserver_cumulative_generation += generation
                clientserver_cumulative_reflection += reflection

                return_dictionary["cs_observer"][timestamp] = {
                    "loss_percentage": compute_loss_ref_gen(generation, reflection), 
                    "generation_#": generation, 
                    "reflection_#": reflection,
                    "cum_loss_percentage": compute_loss_ref_gen(clientserver_cumulative_generation, clientserver_cumulative_reflection), 
                    "cum_generation_#": clientserver_cumulative_generation, 
                    "cum_reflection_#": clientserver_cumulative_reflection}

                if serverclient_last_generation is not None and serverclient_last_reflection is not None and clientserver_last_generation is not None and clientserver_last_reflection is not None:
                    # With this information, we can compute the loss between the observer on the reverse path and the observer on the forward path
                    
                    clientserver_halfloss_cumulative_generation += serverclient_last_generation
                    clientserver_halfloss_cumulative_reflection += clientserver_last_reflection

                    return_dictionary["from_serverclient-observer_to_clientserver-observer"][timestamp] = {
                        "loss_percentage": compute_loss_ref_gen(serverclient_last_generation, clientserver_last_reflection), 
                        "generation_#": serverclient_last_generation, 
                        "reflection_#": clientserver_last_reflection,
                        "cum_loss_percentage": compute_loss_ref_gen(clientserver_halfloss_cumulative_generation, clientserver_halfloss_cumulative_reflection), 
                        "cum_generation_#": clientserver_halfloss_cumulative_generation, 
                        "cum_reflection_#": clientserver_halfloss_cumulative_reflection}

                clientserver_last_generation = generation
                clientserver_last_reflection = reflection


            elif measurements[timestamp]["direction"] == "server_client":

                serverclient_cumulative_generation += generation
                serverclient_cumulative_reflection += reflection

                return_dictionary["sc_observer"][timestamp] = {
                    "loss_percentage": compute_loss_ref_gen(generation, reflection), 
                    "generation_#": generation, 
                    "reflection_#": reflection,
                    "cum_loss_percentage": compute_loss_ref_gen(serverclient_cumulative_generation, serverclient_cumulative_reflection), 
                    "cum_generation_#": serverclient_cumulative_generation, 
                    "cum_reflection_#": serverclient_cumulative_reflection}
                if clientserver_last_generation is not None and clientserver_last_reflection is not None:
                    # With this information, we can compute the loss between the observer on the forward path and the observer on the reverse path

                    serverclient_halfloss_cumulative_generation_phase1 += generation
                    serverclient_halfloss_cumulative_generation_phase2 += reflection
                    serverclient_halfloss_cumulative_reflection_phase1 += clientserver_last_generation
                    serverclient_halfloss_cumulative_reflection_phase2 +=  clientserver_last_reflection
                    
                    return_dictionary["from_clientserver-observer_to_serverclient-observer"][timestamp] = {
                        "phase1_loss_percentage": compute_loss_ref_gen(generation, clientserver_last_generation), 
                        "phase1_generation_#": generation,
                        "phase1_reflection_#": clientserver_last_generation,
                        "phase2_loss_percentage": compute_loss_ref_gen(reflection, clientserver_last_reflection),
                        "phase2_generation_#": reflection,
                        "phase2_reflection_#": clientserver_last_reflection,
                        "cum_phase1_loss_percentage": compute_loss_ref_gen(serverclient_halfloss_cumulative_generation_phase1, serverclient_halfloss_cumulative_reflection_phase1), 
                        "cum_phase1_generation_#": serverclient_halfloss_cumulative_generation_phase1,
                        "cum_phase1_reflection_#": serverclient_halfloss_cumulative_reflection_phase1,
                        "cum_phase2_loss_percentage": compute_loss_ref_gen(serverclient_halfloss_cumulative_generation_phase2, serverclient_halfloss_cumulative_reflection_phase2),
                        "cum_phase2_generation_#": serverclient_halfloss_cumulative_generation_phase2,
                        "cum_phase2_reflection_#": serverclient_halfloss_cumulative_reflection_phase2}

                serverclient_last_generation = generation
                serverclient_last_reflection = reflection

    return return_dictionary



def analyze_lbit(lbit_filename, output=False):

    """
    This function takes pre-processed input from the go-based observers and creates plottable results for the L-Bit.  

    Source format:
    10.0.1.1-10.0.1.2-10000-1234,2021-03-17 16:59:46.722122 +0000 UTC,false
    """

    if output:
        print("analyze_lbit")


    ## Prepare the return dictionary
    return_dictionary = {   "2dir_observer" : {}, 
                            "cs_observer" : {},
                            "sc_observer" : {}}
    
    with open(lbit_filename) as inputFile:

        clientserver_loss = 0
        clientserver_packets = 0
        serverclient_loss = 0
        serverclient_packets = 0

        for line in inputFile:

            content = line.split(",")

            src = str(content[0].split("-")[0])

            timestamp = content[1]
            timestamp = parseDateTime_withErrorHandling(timestamp)

            if "false" in content[2]:
                drop = False
            elif "true" in content[2]:
                drop = True
            direction = "client_server" if src == "10.0.1.1" else "server_client"

            if direction == "client_server":

                if drop:
                    clientserver_loss += 1
                clientserver_packets += 1

                return_dictionary["cs_observer"][timestamp] = {   "loss_percentage": compute_loss_packet_count(clientserver_packets, clientserver_loss),
                                                                            "lost_packets_#": clientserver_loss,
                                                                            "overall_packets_#": clientserver_packets}

            elif direction == "server_client":

                if drop:
                    serverclient_loss += 1
                serverclient_packets += 1

                return_dictionary["sc_observer"][timestamp] = {   "loss_percentage": compute_loss_packet_count(serverclient_packets, serverclient_loss),
                                                                            "lost_packets_#": serverclient_loss,
                                                                            "overall_packets_#": serverclient_packets}

            return_dictionary["2dir_observer"][timestamp] = {    
                "loss_percentage": compute_loss_packet_count(serverclient_packets + clientserver_packets, serverclient_loss + clientserver_loss),
                "lost_packets_#": serverclient_loss + clientserver_loss,
                "overall_packets_#": serverclient_packets + clientserver_packets}
    
    return return_dictionary



def analyze_qbit(qbit_filename, output=False):

    """
    This function takes pre-processed input from the go-based observers and creates plottable results for the Q-Bit.  

    Source format:
    10.0.1.1-10.0.1.2-10000-1234,2021-03-17 09:50:38.669383 +0000 UTC,2021-03-17 09:50:38.880627 +0000 UTC,Phase: 0,Count: 59,Nominal Length:64,X Value:0
    """

    if output:
        print("analyze_qbit")
    
    with open(qbit_filename) as inputFile:

        measurements = {}
        for line in inputFile:

            content = line.split(",")

            src = str(content[0].split("-")[0])

            start_timestamp = content[1]
            end_timestamp = content[2]
            start_timestamp = parseDateTime_withErrorHandling(start_timestamp)
            end_timestamp = parseDateTime_withErrorHandling(end_timestamp)

            phase = int(content[3].split(":")[1].strip(" "))

            count = int(content[4].split(":")[1].strip(" "))

            nominal_count = int(content[5].split(":")[1].strip(" "))

            measurements[end_timestamp] = {"direction" : "client_server" if src == "10.0.1.1" else "server_client",
                                            "#": count,
                                            "nominal_#": nominal_count,
                                            "phase": phase}


        return_dictionary = {   "2dir_observer" : {}, 
                                "cs_observer" : {},
                                "sc_observer" : {}}

        bidirectional_cumulative_nominal = 0
        bidirectional_cumulative_count = 0
        clientserver_cumulative_nominal = 0
        clientserver_cumulative_count = 0
        serverclient_cumulative_nominal = 0
        serverclient_cumulative_count = 0

        for timestamp in sorted(measurements.keys()):

            nominal = measurements[timestamp]["nominal_#"]
            bidirectional_cumulative_nominal += nominal
            count = measurements[timestamp]["#"] 
            bidirectional_cumulative_count += count

            return_dictionary["2dir_observer"][timestamp] = {
                "loss_percentage": compute_loss_nominal_count(nominal, count), 
                "nominal_#": nominal, 
                "qbit_#": count,
                "cum_loss_percentage": compute_loss_nominal_count(bidirectional_cumulative_nominal, bidirectional_cumulative_count), 
                "cum_nominal_#": bidirectional_cumulative_nominal, 
                "cum_qbit_#": bidirectional_cumulative_count}


            if measurements[timestamp]["direction"] == "client_server":

                clientserver_cumulative_nominal += nominal
                clientserver_cumulative_count += count

                return_dictionary["cs_observer"][timestamp] = {
                    "loss_percentage": compute_loss_nominal_count(nominal, count), 
                    "nominal_#": nominal, 
                    "qbit_#": count,
                    "cum_loss_percentage": compute_loss_nominal_count(clientserver_cumulative_nominal, clientserver_cumulative_count), 
                    "cum_nominal_#": clientserver_cumulative_nominal, 
                    "cum_qbit_#": clientserver_cumulative_count}

            elif measurements[timestamp]["direction"] == "server_client":

                serverclient_cumulative_nominal += nominal
                serverclient_cumulative_count += count 

                return_dictionary["sc_observer"][timestamp] = {
                    "loss_percentage": compute_loss_nominal_count(nominal, count), 
                    "nominal_#": nominal, 
                    "qbit_#": count,
                    "cum_loss_percentage": compute_loss_nominal_count(serverclient_cumulative_nominal, serverclient_cumulative_count), 
                    "cum_nominal_#": serverclient_cumulative_nominal, 
                    "cum_qbit_#": serverclient_cumulative_count}

    return return_dictionary


def analyze_rbit(rbit_filename,output=False):

    """
    This function takes pre-processed input from the go-based observers and creates plottable results for the R-Bit.  

    Source format:
    10.0.1.1-10.0.1.2-10000-1234,2021-03-17 10:08:15.616337 +0000 UTC,2021-03-17 10:08:15.795899 +0000 UTC,Phase: 1,Count: 60,Nominal Length:64,X Value:0
    
    Note that the output of the rbit alone is the 3/4 loss. More specifically, the loss of the opposite direction + the loss from the sender to the observer.
    """
    if output:
        print("analyze_rbit")
    
    with open(rbit_filename) as inputFile:

        measurements = {}
        for line in inputFile:

            content = line.split(",")

            src = str(content[0].split("-")[0])

            start_timestamp = content[1]
            end_timestamp = content[2]
            start_timestamp = parseDateTime_withErrorHandling(start_timestamp)
            end_timestamp = parseDateTime_withErrorHandling(end_timestamp)

            phase = int(content[3].split(":")[1].strip(" "))

            count = int(content[4].split(":")[1].strip(" "))

            nominal_count = int(content[5].split(":")[1].strip(" "))

            measurements[end_timestamp] = {"direction" : "client_server" if src == "10.0.1.1" else "server_client",
                                            "#": count,
                                            "nominal_#": nominal_count,
                                            "phase": phase}  

        return_dictionary = {   "2dir_observer" : {}, 
                                "cs_observer" : {},
                                "sc_observer" : {}}

        bidirectional_cumulative_nominal = 0
        bidirectional_cumulative_count = 0
        clientserver_cumulative_nominal = 0
        clientserver_cumulative_count = 0
        serverclient_cumulative_nominal = 0
        serverclient_cumulative_count = 0
        for timestamp in sorted(measurements.keys()):

            nominal = measurements[timestamp]["nominal_#"]
            bidirectional_cumulative_nominal += nominal
            count = measurements[timestamp]["#"] 
            bidirectional_cumulative_count += count

            return_dictionary["2dir_observer"][timestamp] = {
                "loss_percentage": compute_loss_nominal_count(nominal, count), 
                "nominal_#": nominal, 
                "rbit_#": count,
                "cum_loss_percentage": compute_loss_nominal_count(bidirectional_cumulative_nominal, bidirectional_cumulative_count), 
                "cum_nominal_#": bidirectional_cumulative_nominal, 
                "cum_rbit_#": bidirectional_cumulative_count}


            if measurements[timestamp]["direction"] == "client_server":

                clientserver_cumulative_nominal += nominal
                clientserver_cumulative_count += count

                return_dictionary["cs_observer"][timestamp] = {
                    "loss_percentage": compute_loss_nominal_count(nominal, count), 
                    "nominal_#": nominal, 
                    "rbit_#": count,
                    "cum_loss_percentage": compute_loss_nominal_count(clientserver_cumulative_nominal, clientserver_cumulative_count), 
                    "cum_nominal_#": clientserver_cumulative_nominal, 
                    "cum_rbit_#": clientserver_cumulative_count}

            elif measurements[timestamp]["direction"] == "server_client":

                serverclient_cumulative_nominal += nominal
                serverclient_cumulative_count += count 

                return_dictionary["sc_observer"][timestamp] = {
                    "loss_percentage": compute_loss_nominal_count(nominal, count), 
                    "nominal_#": nominal, 
                    "rbit_#": count,
                    "cum_loss_percentage": compute_loss_nominal_count(serverclient_cumulative_nominal, serverclient_cumulative_count), 
                    "cum_nominal_#": serverclient_cumulative_nominal, 
                    "cum_rbit_#": serverclient_cumulative_count}

    return return_dictionary



def determine_groundtruth_Loss(filename_groundtruth_loss_clientswitch, filename_groundtruth_loss_serverswitch, filename_groundtruth_loss_switchclient, filename_groundtruth_loss_switchserver, paper_eval_file=None, output=False):

    """
    This function takes pre-processed input from the go-based observers and creates plottable results for groundtruth loss.  

    The first four files contain the number of lost packets for the different segments.
    The paper_eval_file contains the loss information for the link under study in the paper.

    """

    if output:
        print("determine Loss groundtruth")

    return_dictionary = {   "clientswitch" : {},
                            "switchserver" : {},
                            "cs" : {},
                            "serverswitch" : {},
                            "switchclient" : {},
                            "sc" : {}}

    loss_clientserver_preprocess = {}
    loss_serverclient_preprocess = {}
    
    ### Client-Server Direction
    with open(filename_groundtruth_loss_clientswitch) as inputFile:

        counter = 0
        for line in inputFile:
            counter += 1

            content = line.split(",")

            timestamp = parseDateTime_withErrorHandling(content[0])
            overall_loss = int(content[1])
            return_dictionary["clientswitch"][timestamp] = {"count_overall_packets": counter, "count_loss": overall_loss, "loss_percentage": compute_loss_packet_count(counter, overall_loss)}

            loss_clientserver_preprocess[timestamp] = {"overall_hits_clientswitch": counter, "overall_loss_clientswitch": overall_loss}


    with open(filename_groundtruth_loss_switchserver) as inputFile:

        counter = 0
        for line in inputFile:
            counter += 1

            content = line.split(",")

            timestamp = parseDateTime_withErrorHandling(content[0])
            overall_loss = int(content[1])

            return_dictionary["switchserver"][timestamp] = {"count_overall_packets": counter, "count_loss": overall_loss, "loss_percentage": compute_loss_packet_count(counter, overall_loss)}
            if timestamp in loss_clientserver_preprocess.keys():

                loss_clientserver_preprocess[timestamp]["overall_hits_switchserver"] = counter
                loss_clientserver_preprocess[timestamp]["overall_loss_switchserver"] = overall_loss
            else:
                loss_clientserver_preprocess[timestamp] = {"overall_hits_switchserver": counter, "overall_loss_switchserver": overall_loss}


    with open(paper_eval_file) as inputFile:

        losscounter = 0
        packetCounter = 0

        tempDict = {}

        for line in inputFile:
 
            content = line.split(",")

            if content[0] == "losscount":


                timestamp = parseDateTime_withErrorHandling(content[1])
                overall_loss = int(content[2])

                if timestamp not in tempDict.keys():
                    tempDict[timestamp] = {}
                tempDict[timestamp]["overall_loss"] = overall_loss


            elif content[0] == "overallcount":

                timestamp = parseDateTime_withErrorHandling(content[1])
                overall_packets = int(content[2])
            
                if timestamp not in tempDict.keys():
                    tempDict[timestamp] = {}
                tempDict[timestamp]["overall_packets"] = overall_packets


        losscounter = 0
        packetCounter = 0


        for timestamp in sorted(tempDict.keys()):

            if "overall_packets" in tempDict[timestamp].keys():

                packetCounter = tempDict[timestamp]["overall_packets"]

            if "overall_loss" in tempDict[timestamp].keys():
                losscounter = tempDict[timestamp]["overall_loss"]


            return_dictionary["switchserver"][timestamp] = {"count_overall_packets": packetCounter, "count_loss": losscounter, "loss_percentage": compute_loss_packet_count(packetCounter, losscounter)}
            if timestamp in loss_clientserver_preprocess.keys():

                loss_clientserver_preprocess[timestamp]["overall_hits_switchserver"] = packetCounter
                loss_clientserver_preprocess[timestamp]["overall_loss_switchserver"] = losscounter
            else:
                loss_clientserver_preprocess[timestamp] = {"overall_hits_switchserver": packetCounter, "overall_loss_switchserver": losscounter}




    ### Server-Client Direction
    with open(filename_groundtruth_loss_serverswitch) as inputFile:

        counter = 0
        for line in inputFile:
            counter += 1

            content = line.split(",")

            timestamp = parseDateTime_withErrorHandling(content[0])
            overall_loss = int(content[1])
            return_dictionary["serverswitch"][timestamp] = {"count_overall_packets": counter, "count_loss": overall_loss, "loss_percentage": compute_loss_packet_count(counter, overall_loss)}
            loss_serverclient_preprocess[timestamp] = {"overall_hits_serverswitch": counter, "overall_loss_serverswitch": overall_loss}


    with open(filename_groundtruth_loss_switchclient) as inputFile:

        counter = 0
        for line in inputFile:
            counter += 1

            content = line.split(",")

            timestamp = parseDateTime_withErrorHandling(content[0])
            overall_loss = int(content[1])

            return_dictionary["switchclient"][timestamp] = {"count_overall_packets": counter, "count_loss": overall_loss, "loss_percentage": compute_loss_packet_count(counter, overall_loss)}
            if timestamp in loss_serverclient_preprocess.keys():

                loss_serverclient_preprocess[timestamp]["overall_hits_switchclient"] = counter
                loss_serverclient_preprocess[timestamp]["overall_loss_switchclient"] = overall_loss
            else:
                loss_serverclient_preprocess[timestamp] = {"overall_hits_switchclient": counter, "overall_loss_switchclient": overall_loss}


    latest_clientswitch_count = None
    latest_clientswitch_loss = None
    latest_switchserver_count = None
    latest_switchserver_loss = None

    for sorted_timestamp in sorted(loss_clientserver_preprocess.keys()):

        if "overall_hits_clientswitch" in loss_clientserver_preprocess[sorted_timestamp].keys():

            latest_clientswitch_count = loss_clientserver_preprocess[sorted_timestamp]["overall_hits_clientswitch"]
            latest_clientswitch_loss = loss_clientserver_preprocess[sorted_timestamp]["overall_loss_clientswitch"]

        if "overall_hits_switchserver" in loss_clientserver_preprocess[sorted_timestamp].keys():
            latest_switchserver_count = loss_clientserver_preprocess[sorted_timestamp]["overall_hits_switchserver"]
            latest_switchserver_loss = loss_clientserver_preprocess[sorted_timestamp]["overall_loss_switchserver"]

        if latest_clientswitch_count is not None and latest_clientswitch_loss is not None and latest_switchserver_count is not None and latest_switchserver_loss is not None:

            return_dictionary["cs"][sorted_timestamp] = { "loss_percentage": compute_loss_packet_count(latest_clientswitch_count, latest_clientswitch_loss + latest_switchserver_loss), 
                                                                    "count_overall_packets": latest_clientswitch_count,
                                                                    "count_loss": latest_clientswitch_loss + latest_switchserver_loss}

    latest_serverswitch_count = None
    latest_serverswitch_loss = None
    latest_switchclient_count = None
    latest_switchclient_loss = None
    for sorted_timestamp in sorted(loss_serverclient_preprocess.keys()):

        if "overall_hits_serverswitch" in loss_serverclient_preprocess[sorted_timestamp].keys():

            latest_serverswitch_count = loss_serverclient_preprocess[sorted_timestamp]["overall_hits_serverswitch"]
            latest_serverswitch_loss = loss_serverclient_preprocess[sorted_timestamp]["overall_loss_serverswitch"]

        if "overall_hits_switchclient" in loss_serverclient_preprocess[sorted_timestamp].keys():
            latest_switchclient_count = loss_serverclient_preprocess[sorted_timestamp]["overall_hits_switchclient"]
            latest_switchclient_loss = loss_serverclient_preprocess[sorted_timestamp]["overall_loss_switchclient"]

        if latest_serverswitch_count is not None and latest_serverswitch_loss is not None and latest_switchclient_count is not None and latest_switchclient_loss is not None:

            return_dictionary["sc"][sorted_timestamp] = { "loss_percentage": compute_loss_packet_count(latest_serverswitch_count, latest_serverswitch_loss + latest_switchclient_loss), 
                                                                    "count_overall_packets": latest_serverswitch_count,
                                                                    "count_loss": latest_serverswitch_loss + latest_switchclient_loss}


    return return_dictionary



def analyze_loss_scenarios(preprocessed_folder, pickles_folder):
 
    """
    Wrapper function which performs the analysis of all loss techniques.
    """

    types = ["lossrandom", "lossgemodel"]
    types += ["50k!lossrandom", "500k!lossrandom", "2M!lossrandom", "10M!lossrandom", "200k!lossrandom", "100k!lossrandom", "300k!lossrandom", "20M!lossrandom", "50M!lossrandom", "1M!lossrandom"]
    typeSet = set()

    prefixSet = set()
    for filename in os.listdir(preprocessed_folder):

        if filename.count('+-+') == 2:

            prefix = "+-+".join(filename.split('+-+')[:2])
            prefixSet.add(prefix)

            for possible_type in types:

                if prefix.split("-")[0] == possible_type:
                    typeSet.add(possible_type)

    print(prefixSet)
    for network_error in typeSet:

        print("Process measurement results for Network Setting: {}".format(network_error))
        ### Determine all the different configurations so that they are performed in a bunch
        config_values = set()
        for prefix in prefixSet:

            if network_error == prefix.split("-")[0]:

                prefix_tmp = prefix.split("+-+")[0]
                network_error = prefix_tmp.split("-")[0]
                config_value = prefix_tmp.split("-")[1]
                iteration = prefix_tmp.split("-")[2]

                config_values.add(config_value)



        print("Analyze the following config values: ", config_values)
        for config_value in config_values:
        
            print("Analyze Config Value: ", config_value)
            results_dictionary = {}

            timer = time.perf_counter()

            for prefix in prefixSet:

                if network_error == prefix.split("-")[0] and config_value == prefix.split("+-+")[0].split("-")[1]:
                    iteration = prefix.split("+-+")[0].split("-")[2]
                    print("Configuration: {}, Iteration: {}".format(config_value, iteration))


                    if iteration in results_dictionary.keys():
                        raise Exception("Possible duplicate iterations. Please double check.")
                    results_dictionary[iteration] = {}


                    tbit_filename = os.path.join(preprocessed_folder, prefix + "+-+tbit.csv")
                    tbit_dictionary = analyze_tbit(tbit_filename=tbit_filename)

                    if len(tbit_dictionary["sc_observer"].keys()) > 0:
                        last_timestamp = sorted(tbit_dictionary["sc_observer"].keys())[-1]
                        results_dictionary[iteration]["tbit"] = tbit_dictionary["sc_observer"][last_timestamp]["cum_loss_percentage"]
                    else:
                        results_dictionary[iteration]["tbit"] = -42
                    
                    del tbit_dictionary
                    tbit_dictionary = None


                    lbit_filename = os.path.join(preprocessed_folder, prefix + "+-+lbit.csv")         
                    lbit_dictionary = analyze_lbit(lbit_filename=lbit_filename)

                    if len(lbit_dictionary["sc_observer"].keys()) > 0:
                        last_timestamp = sorted(lbit_dictionary["sc_observer"].keys())[-1]
                        results_dictionary[iteration]["lbit"] = lbit_dictionary["sc_observer"][last_timestamp]["loss_percentage"]
                    else:
                        results_dictionary[iteration]["lbit"] = -42
                    
                    del lbit_dictionary
                    lbit_dictionary = None


                    qbit_filename = os.path.join(preprocessed_folder, prefix + "+-+qbit.csv")
                    qbit_dictionary = analyze_qbit(qbit_filename=qbit_filename)

                    if len(qbit_dictionary["sc_observer"].keys()) > 0:
                        last_timestamp = sorted(qbit_dictionary["sc_observer"].keys())[-1]
                        results_dictionary[iteration]["qbit"] = qbit_dictionary["sc_observer"][last_timestamp]["cum_loss_percentage"]
                    else:
                        results_dictionary[iteration]["qbit"] = -42
                    
                    del qbit_dictionary
                    qbit_dictionary = None


                    rbit_filename = os.path.join(preprocessed_folder, prefix + "+-+rbit.csv")
                    rbit_dictionary = analyze_rbit(rbit_filename=rbit_filename)

                    if len(rbit_dictionary["sc_observer"].keys()) > 0:
                        last_timestamp = sorted(rbit_dictionary["sc_observer"].keys())[-1]
                        results_dictionary[iteration]["rbit"] = rbit_dictionary["sc_observer"][last_timestamp]["cum_loss_percentage"]
                    else:
                        results_dictionary[iteration]["rbit"] = -42
                    
                    del rbit_dictionary
                    rbit_dictionary = None

                    ### Determine Groundtruth
                    filename_groundtruth_loss_clientswitch = os.path.join(preprocessed_folder, prefix + "+-+groundtruth_loss_clientswitch.csv")
                    filename_groundtruth_loss_serverswitch = os.path.join(preprocessed_folder, prefix + "+-+groundtruth_loss_serverswitch.csv")
                    filename_groundtruth_loss_switchclient = os.path.join(preprocessed_folder, prefix + "+-+groundtruth_loss_switchclient.csv")
                    filename_groundtruth_loss_switchserver = os.path.join(preprocessed_folder, prefix + "+-+groundtruth_loss_switchserver.csv")
                    filename_paper_eval = os.path.join(preprocessed_folder, prefix + "+-+groundtruth_overall_packets_and_loss_count.csv")
                    groundtruth_dictionary = determine_groundtruth_Loss(
                        filename_groundtruth_loss_clientswitch=filename_groundtruth_loss_clientswitch,
                        filename_groundtruth_loss_serverswitch=filename_groundtruth_loss_serverswitch,
                        filename_groundtruth_loss_switchclient=filename_groundtruth_loss_switchclient,
                        filename_groundtruth_loss_switchserver=filename_groundtruth_loss_switchserver,
                        paper_eval_file=filename_paper_eval
                    )

                    if len(groundtruth_dictionary["switchserver"].keys()) > 0:
                        last_timestamp = sorted(groundtruth_dictionary["switchserver"].keys())[-1]
                        results_dictionary[iteration]["groundtruth"] = groundtruth_dictionary["switchserver"][last_timestamp]["loss_percentage"]
                    else:
                        results_dictionary[iteration]["groundtruth"] = -42
                    
                    del groundtruth_dictionary
                    groundtruth_dictionary = None


            print("Computing took ", time.perf_counter()-timer, " seconds.")
            timer = time.perf_counter()
            print("Store everything in file!")

            groundtruth = []
            lbit = []
            rbit = []
            qbit = []
            tbit = []

            for iteration in results_dictionary.keys():

                groundtruth.append(results_dictionary[iteration]["groundtruth"])
                lbit.append(results_dictionary[iteration]["lbit"])
                tbit.append(results_dictionary[iteration]["tbit"])
                qbit.append(results_dictionary[iteration]["qbit"])
                rbit.append(results_dictionary[iteration]["rbit"])

            with open(os.path.join(pickles_folder, "results_" + network_error + "_" + config_value + "_plot.csv"), "w") as out:
                out.write("Groundtruth")
                for percentage in groundtruth:
                    out.write("," + str(percentage))
                out.write("\n")
                out.write("Lbit")
                for percentage in lbit:
                    out.write("," + str(percentage))
                out.write("\n")
                out.write("Rbit")
                for percentage in rbit:
                    out.write("," + str(percentage))
                out.write("\n")
                out.write("Qbit")
                for percentage in qbit:
                    out.write("," + str(percentage))
                out.write("\n")
                out.write("Tbit")
                for percentage in tbit:
                    out.write("," + str(percentage))
                out.write("\n")
