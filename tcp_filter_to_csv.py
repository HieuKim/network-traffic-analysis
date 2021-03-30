from scapy.all import*
import os
import numpy as np
import time
#from tcp_analysis_pcap import dict_from_2_list_and_cal_total_in_value
#import pyshark
#from collections import Counter
#import matplotlib.pyplot as plt
#from collections import defaultdict
import ipaddress
def packet_count(numpy_array):
    unique, counts = np.unique(numpy_array, return_counts=True)
    unique_counts = np.column_stack([unique, counts])
    return unique_counts
def dict_from_2_list_and_cal_total_in_value(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    temp = {k: sum(v) for k, v in temp.items()}  # Calculating the sum of all value in each key.
    temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp
#file_name='/home/mpec/hust_traffic_pcap/11h->12h/test_0'  # hust's data test0
start=time.time()
duration = 2 # seconds
freq = 440  ## Hz
index_max=2000
print("Processing...")
#file_name = '/home/mpec/Desktop/pcap_analysis/ddostrace.to-victim.20070804_140436.pcap'
#pkts=rdpcap(file_name)
for index_file in range(0,index_max+1,1):
    #file_name = "/home/mpec/hust_traffic_pcap/11h->12h/test_" + str(index_file)
    #file_name= "/media/mpec/eb38a860-81a7-43f8-9205-6df6e098435f/income/inC_367_file" + str(index_file) + ".pcap"
    #file_name = "/media/mpec/eb38a860-81a7-43f8-9205-6df6e098435f/outcome/outGoing_367_file" + str(index_file)
    #file_name = "/media/mpec/eb38a860-81a7-43f8-9205-6df6e098435f/file_368/outGoing/outGoing368_splitted" + str(index_file)
    file_name = "/media/mpec/eb38a860-81a7-43f8-9205-6df6e098435f/file_368/inComing/inComing368_splitted" + str(index_file)
    print("Working with file: ", index_file, file_name)
    '''Matrix startup'''
    matrix_ip = np.empty([1, 1])
    #print(matrix_ip_sport_len)
    start1= time.time()
    #b = sniff(offline=file_name,filter = 'tcp[tcpflags] & tcp-syn != 0')
    b=sniff(offline=file_name)
    sniffing_time = time.time()
    print("Sniffing time: ", sniffing_time - start1)
    # ip_decimal=[]
    # src_port=[]
    # data_length=[]
    print(len(b))
    #print(b[0].show())
    for j in b:
        if j.haslayer(IP) == 1:
            matrix_ip = np.vstack([matrix_ip, [int(ipaddress.ip_address(j['IP'].dst))]])
            #matrix_ip = np.vstack([matrix_ip, [int(ipaddress.ip_address(j['IP'].src)), j['IP'].len]])
            #matrix_ip = np.vstack([matrix_ip, [int(ipaddress.ip_address(j['IP'].dst)), j['IP'].len]])
            #matrix_ip_sport_len = np.vstack([matrix_ip_sport_len],
            #                                 [int(ipaddress.ip_address(b[j]['IP'].src)),int(b[j].dport),int(b[j].sport)])
            #matrix_ip=np.vstack([matrix_ip,[int(ipaddress.ip_address(j['IP'].src))]])
    '''Packet Count'''
    matrix_ip = np.delete(matrix_ip, 0, axis=0)
    unique_counts_new = packet_count(matrix_ip)
    print(unique_counts_new)
    print(unique_counts_new.shape)
    '''Packet len Calculation'''
    '''
    matrix_ip = np.delete(matrix_ip, 0, axis=0)
    newdic = dict_from_2_list_and_cal_total_in_value(matrix_ip[:, 0], matrix_ip[:, 1])
    print(newdic)
    Ip_list = np.array(list(newdic.keys()))
    Pkt_len = np.array(list(newdic.values()))
    Ip_Len_Array = np.vstack([Ip_list, Pkt_len])
    Ip_Len_Array = np.transpose(Ip_Len_Array, axes=None)
    print(Ip_Len_Array)
    print('Shape:', Ip_Len_Array.shape)
    '''
    '''Save an array to a text file'''
    if index_file == 0:
        with open('InComing368_packets.csv', 'w') as f:
            np.savetxt(f,unique_counts_new , delimiter=',', fmt='%d')  # ip_src,s_port,length,ip_dst,d_port,proto
    else:
        #saved_file= 'test'+ str(index_file)+'.csv'
        with open('InComing368_packets.csv', 'a') as f:
            np.savetxt(f, unique_counts_new, delimiter=',', fmt='%d')  # ip_src,s_port,length,ip_dst,d_port,proto
end = time.time()
print("exe time: ", end - start)
os.system('play -nq -t alsa synth {} sine {}'.format(duration, freq))
#filtered = (pkt for pkt in pkts if not (TCP in pkt or UDP in pkt or ICMP in pkt))
#print(filtered)
#print('the number of packet in file test_0: ', filtered)
'''
matrix1=[0,1,2]
a= np.array([matrix1[0],matrix1[1],matrix1[2]])
a=np.vstack([a,[1,2,3]]) #vstack  vertical stack append
# hstack horizontal stack append
print(a)
print(type(a))
'''