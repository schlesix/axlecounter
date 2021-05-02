# BITA - Basic IP Traffic Analyzer

import argparse
import os
import sys
import logging
import hashlib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import getopt
import binascii

# Import für GUI
import tkinter as tk
from tkinter import * 

#main_window = tk.Tk()

# Build Number
buildno = "2021.05.01.1947"

# Tupel für Paket-Metadaten
capture_metadata1 = []
capture_metadata2 = []
input_files = []

# Indizes für die Metadaten-Felder

idx_packet_no = 0
idx_src_ip = 0
idx_dst_ip = 0
# Beim Start übergebene Parameter
arg_show_packets = False # Anzeigen von Diffs auf der CLI
arg_limit_list = 0 # Begrenzen der Diff-Liste auf n Einträge
arg_report_filename="" # Name der Ausgabedatei

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
    # Indizes für die Metadaten
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

# Es gibt auch Pakete ohne Identification (Wert ist auf 0 gesetzt). 
# Um ein Paket in diesem Fall eindeutig zu identifizieren, wird ein Hash-Value aus den Rohdaten des Paketes errechnet, ansonsten aus ein paar Header-Daten (ist das eventuell ein Probem bei virtuellen IPs?).
    print('Reading PCAP {}...'.format(file_name))
    packets = rdpcap(file_name)
    print(str(len(packets))+" Frames read.")
    print("Extracting Metadata from PCAP...")
    count=0
    #global capture_metadataw
    for packet in packets:
        count=count+1
        if 'IP' in packet:
            packetdaten = []
            # Hash berechnen
            raw_packet=str(packet['IP'].payload) 
            hash_object=hashlib.sha256(raw_packet.encode('utf-8'))
            hex_dig=hash_object.hexdigest()
            packetdaten.append(count) 
            idx_packet_no = 0
            packetdaten.append(hex_dig)
            idx_hash = 1
            packetdaten.append(str(packet['IP'].src)) 
            idx_src_ip = 2
            packetdaten.append(str(packet['IP'].dst))
            idx_dst_ip = 3
            packetdaten.append(str(packet['IP'].id))
            idx_ip_ident = 4
            packetdaten.append(str(packet['IP'].len))
            idx_ip_len = 5         
            #xy=str(packet['IP'].src)+";"+str(packet['IP'].dst)+";"+str(packet['IP'].id)
            #eintrag=str(hex_dig)+";"+str(packet['IP'].src)+";"+str(packet['IP'].dst)+";"+str(packet['IP'].id)
            if 'TCP' in packet:
                packetdaten.append("TCP")
                idx_l4_proto = 6   
                packetdaten.append(str(packet['TCP'].sport))
                idx_tcp_src_prt = 7
                packetdaten.append(str(packet['TCP'].dport))
                idx_tcp_dst_prt = 8
                packetdaten.append(str(packet['TCP'].seq))
                idx_tcp_seq = 9
                packetdaten.append(str(packet['TCP'].ack))
                idx_tcp_ack = 10 
                packetdaten.append(str(packet['TCP'].flags))
                idx_tcp_flgs = 11
            elif 'UDP' in packet:
                packetdaten.append("UDP")
                idx_l4_proto = 6    
                packetdaten.append(str(packet['UDP'].sport))
                idx_udp_src_prt = 7
                packetdaten.append(str(packet['UDP'].dport))
                idx_udp_dst_prt = 8
                packetdaten.append("./.") # 9
                packetdaten.append("./.") # 10
                packetdaten.append("./.") # 11            
                #eintrag=eintrag+";UDP"
                #eintrag=eintrag+";"+str(packet['UDP'].sport)+";"+str(packet['UDP'].dport)
            else:
                packetdaten.append("./.")  #6        
                packetdaten.append("./.")  #7 
                packetdaten.append("./.")  #8      
                packetdaten.append("./.")  #9         
                packetdaten.append("./.")  #10
                packetdaten.append("./.")  #11
            metadata.append(packetdaten)
            #metadata.append(eintrag)

def usage():
    print("RTFM!")

def getparam():
    global input_files
    global arg_show_packets
    global arg_limit_list
    global arg_report_filename
    try:
        cmd_opts = "cf:i:L:lo:z:qrd"
        opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
    except getopt.GetoptError:
        print("F:" + getopt.GetoptError)
        usage()
    for opt in opts:
        if opt[0] == "-i":
            input_files.append(opt[1])
        if opt[0] == "-d":
            arg_show_packets = True
        if opt[0] == "-z":
            arg_limit_list=int(opt[1])
        if opt[0] == "-o":
            arg_report_filename=opt[1]
def find_startingoffset_alt():
    global capture_metadata1
    global capture_metadata2
    offset=0
    i=0
    while i<len(capture_metadata1) and offset==0:
        try:
            offset = capture_metadata2.index(capture_metadata1[i])-i
        except ValueError:
            print("fso:Fehler!")
            offset = 0
        if offset>0:
            return i+1, i+1+offset;
            print("Erste gemeinsame Zeile "+str(i+1)+": "+capture_metadata1[i]+" -> "+str(i+1+offset))
            break
        i=i+1
    return 0,0; 

def find_startingoffset():
    global idx_hash

    global capture_metadata1
    global capture_metadata2
    offset=0
    i=0
    j=0
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
    # Muss noch anständig programmiert werden, kann so nicht funktionieren
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
    for record in capture_metadata2:
        if record[1]==chksum:
            return 1
    return 0

def print_missing_packets(source_file_name, report_file_name, max, start_at_line):
    # Feldindizes Metadaten
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
    # Verbesserungen:
    # TCP-Flags, z. B. [FIN,ACK]
    # Seq=... , Ack=..., Win=..., Len=...
    print("Finding missing packets...")
    if os.path.exists(report_file_name):
        os.remove(report_file_name)
    L3TrafficFile = open(report_file_name, 'w')
    L3TrafficFile.write("# Created with ls , Build " + buildno+"\n")
    L3TrafficFile.write("# Source file: " +source_file_name+"\n")
    if (start_at_line>0):
        L3TrafficFile.write("Starting at Packet " + str(start_at_line)+ " (first common packet)\n")
        print("Starting at Packet " + str(start_at_line)+ " (first common packet)\n")
    L3TrafficFile.write("k\n")
    i=0
    listsize=0
    for record in capture_metadata1:
        # Gewünschten Maximalwert von Listeneinträgen nicht überschreiten
        if listsize>=arg_limit_list:
            break
        # Prüfen, ob in beide
        # if 5 in [data.n for data in myList]:
        if  find_checksum(record[idx_hash])==0:
            reportline='{:6s}'.format(str(record[idx_packet_no]).rjust(5))
            reportline=reportline+'{:13s}'.format(str(record[idx_src_ip]))+" -> "+'{:13s}'.format(str(record[idx_dst_ip]))
            reportline=reportline+' '+'{:5s}'.format(str(record[idx_l4_proto]))
            if record[idx_l4_proto]=="UDP":
                reportline=reportline+' '+'{:5s}'.format(str(record[idx_udp_src_prt]))+" -> "+'{:5s}'.format(str(record[idx_udp_dst_prt]))
            if record[6]=="TCP":
                reportline=reportline+' '+'{:5s}'.format(str(record[idx_tcp_src_prt]))+" -> "+'{:5s}'.format(str(record[idx_tcp_src_prt]))
                reportline=reportline+' '+'{:10s} Flags:'.format(str(record[idx_tcp_flgs]))        
            reportline=reportline+" (IP Len="+(str(record[idx_ip_len]))+" Byte)"
            if i>=start_at_line:
                L3TrafficFile.write(str(reportline)+'\n')
                listsize=listsize+1
                if arg_show_packets==True:
                    print(reportline)
            i=i+1

    L3TrafficFile.close()
    return 0

def main():
    global input_files
    global arg_report_filename
    print("Axle Counter, Build "+buildno)
    getparam()
    #for zeile in input_files:
    #    process_pcap(zeile)
    if len(input_files)!=2:
        print("Please name two input files (-i filename)!")
    else:
        process_pcap(input_files[0], capture_metadata1)
        process_pcap(input_files[1], capture_metadata2)
        print("Detecting starting offset...")
        first_common_line1, first_common_line2 = find_startingoffset()
        #print("First common line: "+str(first_common_line1)+" / "+str(first_common_line2))
        if arg_report_filename=="":
            arg_report_filename=input_files[0]+".txt"
        print_missing_packets(input_files[0], arg_report_filename,arg_limit_list,first_common_line1)

if __name__ == "__main__":
    # execute only if run as a script
    main()