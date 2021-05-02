#!/usr/bin/python3
#
# Axle Counter
#
# written by Thomas Schlesinger, schlesix@gmail.com
#
# The programm compares to pcap/pcapng file and list the packets
# being in the first file, but not in the second one.
# 
# It auto-syncs the start of the two files, meaning
# - it searches the first packet occuring in both files and ignoring
#   the noise before that point.
# The idea behind it is that you often aren't able to take to captures,
# starting with the very same packet at to points simultaneously.
#
# The differences are written in a report file (plain text) and can be
# printed on the console, if desired.
#
# The application is cli-only at the moment, but I want do add GUI support.

# Import necessary Python modules
import argparse
import os
import sys
import logging
import hashlib
# The next line supresses unwanted messages from the scapy module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import getopt
import binascii

# Import for GUI
import tkinter as tk
from tkinter import * 

# For later use (GUI)
#main_window = tk.Tk()

# Build Number
buildno = "2021.05.02.2028"

# Tupel for packet metadata
capture_metadata1 = []
capture_metadata2 = []

# Paths of the pcap-files to compare
input_files = []

# Indexes for the fields in the metadata, used for easy
# reordering and expansion 
idx_packet_no = 0
idx_hash = 0
idx_src_ip = 0
idx_dst_ip = 0
idx_ip_ident = 0
idx_ip_len = 0
idx_l4_proto = 0
idx_tcp_src_prt = 0
idx_tcp_dst_prt = 0
idx_tcp_seq = 0
idx_tcp_ack = 0
idx_tcp_flgs = 0
idx_udp_src_prt = 0
idx_udp_dst_prt = 0

# Arguments from program call (cli)
# 
# Show diffs on cli
arg_show_packets = False
# Limit reported diffs in volume
arg_limit_list = 0 
# Path of the report file
arg_report_filename=""

# Not currently used, some GUI code
def zeige_diff():
    global capture_metadata1
    global capture_metadata2

    # Main Frame erzeugen
    settings_frame=Frame(main_window)
    settings_frame.pack()
    Label(settings_frame, text="Setting 1").grid(row=0, column=0)
 
    attributes_frame=Frame(main_window)
    attributes_frame.pack(fill=X)
    Label(attributes_frame, text="Packet #", width=5, fg="blue", anchor='w').grid(row=1, column=0)
    Label(attributes_frame, text="Erste Spalte", width=10, fg="blue", anchor='w').grid(row=1, column=1)
    Label(attributes_frame, text="", width=1).grid(row=1, column=2)
    Label(attributes_frame, text="Zweite Spalte", fg="blue", width=20, anchor='w').grid(row=1, column=3)


    main_frame = Frame(main_window)
    main_frame.pack(fill=BOTH, expand=1)

    # Canvas erzeugen
    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    # Scrollbar zu Canvas hinzufügen
    my_scrollbar = tk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT,fill=Y)

    # Canvas konfigurieren
    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all"))) 
    # Weiteren Frame innerhalb des Canvas erzeugen
    second_frame=Frame(my_canvas)
    # Diesen weiteren Frame in ein Fenster in der Canvas einfügen
    my_canvas.create_window((0,0), window=second_frame, anchor="nw")
    i=0
    while (i<len(capture_metadata1) and (i<len(capture_metadata2))):
        Label(second_frame, text=str(i), fg="grey", width=5, anchor='w').grid(row=i, column=0)
        if i<len(capture_metadata1):
            zeile=capture_metadata1[i]
            feld=zeile.split(';')
            Label(second_frame, text=feld[1], bg="red", width=50, anchor='w').grid(row=i, column=1)
        else:
            Label(second_frame, text="", bg="red", width=50, anchor='w').grid(row=i, column=1)
        Label(second_frame, text=" ", width = 1).grid(row=i, column=2)
        if i<len(capture_metadata2):
            zeile=capture_metadata2[i]
            feld=zeile.split(';')        
            Label(second_frame, text=feld[1], width = 20, bg="green", anchor='w').grid(row=i, column=3)
        else:
            Label(second_frame, text="", width = 20, bg="green", anchor='w').grid(row=i, column=3)
        i=i+1
    main_window.mainloop()
    return 0


def process_pcap(file_name, metadata):
    """
    Reads a pcap(ng) file and extracts the metadata into a list

    Parameters:
    - filename -> Path to pcap(ng) file
    - metadata -> list for storing the metadata
    """

    # Indexes of the metadata
    #
    # Metadata is being added in this function, therefore it is the place where reordering
    # of the sequence will occur.
    # The position of the metada field in a 'row' is consequently set here as well.
    #
    global idx_packet_no
    global idx_hash
    global idx_src_ip
    global idx_dst_ip
    global idx_ip_ident
    global idx_ip_len
    global idx_l4_proto
    global idx_tcp_src_prt
    global idx_tcp_dst_prt
    global idx_tcp_seq
    global idx_tcp_ack
    global idx_tcp_flgs
    global idx_udp_src_prt
    global idx_udp_dst_prt

# Opening a pcap(ng) file dor reading
# 
# TODO: 
# - implement try, except
# - research speed optimization for hash calculation (other algorithm?)
# - 'prettify' TCP Flags
#   
    print('Reading PCAP {}...'.format(file_name))
    packets = rdpcap(file_name)
    # Give some livesign to user
    print(str(len(packets))+" Frames read.")
    print("Extracting Metadata from PCAP...")
    
    # Packet counter for easier location of packets in other software, like Wireshark
    packet_count=0
    # Iterate through all packets in the capture file
    for packet in packets:
        packet_count=packet_count+1
        # Ignore packet that are no IP packets
        if 'IP' in packet:
            # metadata for the current packet
            packetdaten = []
            packetdaten.append(packet_count)
            idx_packet_no = 0
            # Sometimes, the packets don't have a proper value in the identification field.
            # This makes it hard to compare two packets.
            # My workaround: calculation a hash on the payload and use that to identify packets.
            #
            # Calculate and write hash value to metadata 'column'
            raw_packet=str(packet['IP'].payload) 
            hash_object=hashlib.sha256(raw_packet.encode('utf-8'))
            hex_dig=hash_object.hexdigest()
            packetdaten.append(hex_dig)
            idx_hash = 1
            # Write Source IP to metadata 'column'
            packetdaten.append(str(packet['IP'].src)) 
            idx_src_ip = 2
            # Write Destination IP to metadata 'column'
            packetdaten.append(str(packet['IP'].dst))
            idx_dst_ip = 3
            # Write IP Identification to metadata 'column' (no always proper set)
            packetdaten.append(str(packet['IP'].id))
            idx_ip_ident = 4
            # Write Length of IP Packet (Layer 3) to metadata 'column'
            packetdaten.append(str(packet['IP'].len))
            idx_ip_len = 5         
            # Handling TCP 
            if 'TCP' in packet:
                # Write L4 protocol type to metadata 'column'
                packetdaten.append("TCP")
                idx_l4_proto = 6   
                # Write TCP source port to metadata 'column'
                packetdaten.append(str(packet['TCP'].sport))
                idx_tcp_src_prt = 7
                # Write TCP destination port to metadata 'column'
                packetdaten.append(str(packet['TCP'].dport))
                idx_tcp_dst_prt = 8
                # Write TCP sequence number to metadata 'column'
                packetdaten.append(str(packet['TCP'].seq))
                idx_tcp_seq = 9
                # Write TCP acknowledgement number to metadata 'column'               
                packetdaten.append(str(packet['TCP'].ack))
                idx_tcp_ack = 10 
                # Write TCP flags to metadata 'column'             
                packetdaten.append(str(packet['TCP'].flags))
                idx_tcp_flgs = 11
            # Handling UDP
            elif 'UDP' in packet:
                # Write L4 protocol type to metadata 'column'
                packetdaten.append("UDP")
                idx_l4_proto = 6    
                # Write UDP source port to metadata 'column'
                packetdaten.append(str(packet['UDP'].sport))
                idx_udp_src_prt = 7
                # Write UDP destination port to metadata 'column'
                packetdaten.append(str(packet['UDP'].dport))
                idx_udp_dst_prt = 8
                # Write empty values to unused field for metadata 'column'
                packetdaten.append("./.") # 9
                packetdaten.append("./.") # 10
                packetdaten.append("./.") # 11            
            # Neither TCP nor UDP
            else:
                # Write empty values to unused field for metadata 'column'
                packetdaten.append("./.")  #6        
                packetdaten.append("./.")  #7 
                packetdaten.append("./.")  #8      
                packetdaten.append("./.")  #9         
                packetdaten.append("./.")  #10
                packetdaten.append("./.")  #11
            # Append metadata for current packet in list (sublist in list)
            metadata.append(packetdaten)
            #metadata.append(eintrag)

def usage():
    """
    Show usage information

    """  

    print("""
    Diff two pcap(ng) files
    Created by Thomas Schlesinger <schlesix@gmail.com>
    Version 0.0.1

    Parameters:

    -i <input_file>  (use two times to specify pcap files)
    -o <output_file> (path to report file)
    -d (display output on stdout, too) 
    -z (limit output to n lines)
 
    Example:
    
    axlecounter.py -i client.pcapng -i server.pcapng -d -z 20 -o report.txt
 
    """)
    sys.exit(1)

def getparam():
    """
    Get command line parameters and set global vars accordingly.

    """  
    global input_files
    global arg_show_packets
    global arg_limit_list
    global arg_report_filename
    try:
        cmd_opts = "cf:i:L:lo:z:qrd"
        opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
        if len(opts)==0:
            usage()     
    except getopt.GetoptError:
        usage()
    for opt in opts:
        # Input files (pcaps)
        if opt[0] == "-i":
            input_files.append(opt[1])
        # Display result to stdout, too
        if opt[0] == "-d":
            arg_show_packets = True
        # Limit report size to first n hits
        if opt[0] == "-z":
            arg_limit_list=int(opt[1])
        # Specify path to report file
        if opt[0] == "-o":
            arg_report_filename=opt[1]


def find_startingoffset():
    """
    Cut 'noise' by finding the first packet from input file 1 that occurs in input file 2
    and return its offset in input file 2

    """  

    # Use global vars
    global idx_hash
    global capture_metadata1
    global capture_metadata2
    # Starting point in input file 2 (return value)
    offset=0
    # Counter
    i=0
    j=0
    # Iterate through each packet of input file 1 and check, wether it occurs in input file 2.
    # If so, return the position in input file 1 and its position in input file 2
    while i<len(capture_metadata1) and offset==0:
        j=0
        row=capture_metadata1[i]
        hashwert=row[idx_hash]
        while j<len(capture_metadata2) and offset==0:
            row2=capture_metadata2[j]
            if row2[idx_hash]==hashwert:
                offset=i
            j=j+1
        i=i+1
    if offset>0:
        return offset,j
    else:
        return 0,0


def find_endingoffset():
    # Not yet usable
    #
    # TODO:
    # - make it work 
    #
    global capture_metadata1
    global capture_metadata2
    offset=0
    len1=len(capture_metadata1)
    len2=len(capture_metadata2)
    i=min(l1,l2)
    while i>0 and offset==0:
        try:
            offset = capture_metadata2.index(capture_metadata1[i])-i
        except ValueError:
            offset = 0
        if offset>0:
            return i+1, i+1+offset;
            #print("Erste gemeinsame Zeile "+str(i+1)+": "+capture_metadata1[i]+" -> "+str(i+1+offset))
            break
        i=i+1
    return 0,0; 

def find_checksum(chksum):
    """
    Find a given checksum in metadata for input file 2

    """  
    for record in capture_metadata2:
        if record[1]==chksum:
            return 1
    return 0

def print_missing_packets(source_file_name, report_file_name, max, start_at_line):
    """
    - Report packets that are in input file 1, but not in input file 2.
    - Write result to report file.
    - Limit list size to 'max' entries
    - Start at packet 'packet_line'
    """ 
    # Field indexes metadata
    global idx_packet_no
    global idx_hash
    global idx_src_ip
    global idx_dst_ip
    global idx_ip_ident
    global idx_ip_len
    global idx_l4_proto
    global idx_tcp_src_prt
    global idx_tcp_dst_prt
    global idx_tcp_seq
    global idx_tcp_ack
    global idx_tcp_flgs
    global idx_udp_src_prt
    global idx_udp_dst_prt

    global arg_show_packets
    global arg_limit_list
    # TODO:
    # - TCP-Flags, z. B. [FIN,ACK]
    # - Seq=... , Ack=..., Win=..., Len=...
    print("Finding missing packets...")
    # Create report file
    if os.path.exists(report_file_name):
        os.remove(report_file_name)
    L3TrafficFile = open(report_file_name, 'w')
    # Write Header in report file
    L3TrafficFile.write("# Created with Axle Counter , Build " + buildno+"\n")
    L3TrafficFile.write("# Source file: " +source_file_name+"\n")
    # 
    if (start_at_line>0):
        L3TrafficFile.write("Starting at Packet " + str(start_at_line)+ " (first common packet)\n")
        print("Starting at Packet " + str(start_at_line)+ " (first common packet)\n")
    L3TrafficFile.write("k\n")
    # Counter for reported lines
    i=0
    listsize=0
    # Iterate through all packets in input file 1
    for record in capture_metadata1:
        # Check, if already max lines are reported -> exit
        if listsize>=arg_limit_list:
            break
        # Check, if packet from input file 1 is also in inout file 2 (hash value)
        if  find_checksum(record[idx_hash])==0:
            # If so, write report line
            reportline='{:6s}'.format(str(record[idx_packet_no]).rjust(5))
            reportline=reportline+'{:13s}'.format(str(record[idx_src_ip]))+" -> "+'{:13s}'.format(str(record[idx_dst_ip]))
            reportline=reportline+' '+'{:5s}'.format(str(record[idx_l4_proto]))
            # Write UDP information
            if record[idx_l4_proto]=="UDP":
                reportline=reportline+' '+'{:5s}'.format(str(record[idx_udp_src_prt]))+" -> "+'{:5s}'.format(str(record[idx_udp_dst_prt]))
            # Write TCP information
            if record[6]=="TCP":
                reportline=reportline+' '+'{:5s}'.format(str(record[idx_tcp_src_prt]))+" -> "+'{:5s}'.format(str(record[idx_tcp_src_prt]))
                reportline=reportline+' '+'{:10s} Flags:'.format(str(record[idx_tcp_flgs]))        
            reportline=reportline+" (IP Len="+(str(record[idx_ip_len]))+" Byte)"
            # Note the offset
            if i>=start_at_line:
                L3TrafficFile.write(str(reportline)+'\n')
                listsize=listsize+1
                if arg_show_packets==True:
                    print(reportline)
            i=i+1
    L3TrafficFile.close()
    return 0

def main():
    """
    - Main function.
    """ 
    global input_files
    global arg_report_filename
    print("\nAxle Counter, Build "+buildno)
    getparam()
    # Check, if two input files are given
    if len(input_files)!=2:
        print("Please name two input files (-i filename)!")
    else:
        # Read input files
        process_pcap(input_files[0], capture_metadata1)
        process_pcap(input_files[1], capture_metadata2)
        # Seach for offset (first usable packet for comparison)
        print("Detecting starting offset...")
        first_common_line1, first_common_line2 = find_startingoffset()
        # If no output file name is given, create one
        if arg_report_filename=="":
            arg_report_filename=input_files[0]+".txt"
        print_missing_packets(input_files[0], arg_report_filename,arg_limit_list,first_common_line1)

if __name__ == "__main__":
    # execute only if run as a script
    main()