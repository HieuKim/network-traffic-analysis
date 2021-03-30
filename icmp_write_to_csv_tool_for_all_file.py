from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import csv
import ipaddress
index_max=300
print("Processing...")
for index_file in range(1,index_max+1,1):
    file_name= "/home/mpec/caida2007_to_victim/144436_tcp_done/test" + str(index_file) + ".pcap"
    print("Working with file: ", index_file, file_name)
    a = sniff(offline=file_name, filter='icmp[icmptype]== icmp-echo and icmp[icmptype] != icmp-echoreply')
    #print("ICMP packets: ", len(a))
    #print(a[0].show())
    # dura_tion= pkts[-1].time-pkts[0].time     # Duration of the whole pcap file
    dura_tion = 1
    icmp_ip_unfilter = []
    icmp_packet_unfilter = [].,
    icmp_ip = []
    pack_per_sec = []
    icmp_ip_decimal=[]
    for j in a:
        if j['IP'].src not in icmp_ip:
            icmp_ip.append(j['IP'].src)
            icmp_ip_decimal.append(int(ipaddress.ip_address(j['IP'].src)))
        icmp_ip_unfilter.append(int(ipaddress.ip_address(j['IP'].src)))  # A list including all the ip address wihtout filtering
        icmp_packet_unfilter.append(j['IP'].len)  # A list including all the packet length without summing them

    '''Calculate the avg the packet length and insert to a list '''
    for val in icmp_ip_decimal:
        total = 0.0
        for index, value in enumerate(icmp_ip_unfilter):
            if val == value:
                total = total + icmp_packet_unfilter[index] / 300
        pack_per_sec.append(total)
    '''Calculate the avg the packet length and insert to a list '''
    #print("IP: ", icmp_ip)
    #print("the number of IP: ", len(icmp_ip))

    #print("ICMP IP slots: ", len(icmp_ip))
    #print('ICMP IP:', icmp_ip)
    #print("bytes/s: ", pack_per_sec)
    matrix_for_csv = np.vstack((icmp_ip, pack_per_sec)).T
    if index_file == 1:
        with open('icmp_analysis_144436.csv', 'w', newline="") as f:  # Exporting to icmp_analysis.csv
            thewriter = csv.writer(f)
            for i in range(len(matrix_for_csv)):
                thewriter.writerow(matrix_for_csv[i])
    else:
        with open('icmp_analysis_144436.csv', 'a', newline="") as f:  # Exporting to icmp_analysis.csv
            thewriter = csv.writer(f)
            for i in range(len(matrix_for_csv)):
                thewriter.writerow(matrix_for_csv[i])
    print("\t {} Done.".format(index_file))

print("Process completed!!!")





