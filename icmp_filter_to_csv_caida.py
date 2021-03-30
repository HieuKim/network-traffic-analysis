from scapy.all import*
import os
import numpy as np
import time
#import pyshark
#from collections import Counter
#import matplotlib.pyplot as plt
#from collections import defaultdict
import ipaddress
#file_name='/home/mpec/hust_traffic_pcap/11h->12h/test_0'  # hust's data test0
start=time.time()
duration = 2 # seconds
freq = 440  ## Hz
index_max=300
print("Processing...")
#file_name = '/home/mpec/Desktop/pcap_analysis/ddostrace.to-victim.20070804_140436.pcap'
#pkts=rdpcap(file_name)
for index_file in range(1,index_max+1,1):
    #file_name = "/home/mpec/hust_traffic_pcap/11h->12h/test_" + str(index_file)
    file_name= "/home/mpec/caida2007_to_victim/141436/test" + str(index_file) + ".pcap"
    print("Working with file: ", index_file, file_name)
    matrix_ip_sport_len = np.empty([1, 2])
    print(matrix_ip_sport_len)
    start1= time.time()
    b = sniff(offline=file_name,filter = 'icmp[icmptype] == icmp-echo and icmp[icmptype] != icmp-echoreply')
    sniffing_time = time.time()
    print("Sniffing time: ", sniffing_time - start1)
    # ip_decimal=[]
    # src_port=[]
    # data_length=[]
    print(len(b))
    print(b[0].show())
    for j in range(len(b)):
        if b[j].haslayer(IP) == 1:
            matrix_ip_sport_len = np.vstack([matrix_ip_sport_len, [int(ipaddress.ip_address(b[j]['IP'].src)),b[j]['IP'].len]])
    matrix_ip_sport_len = np.delete(matrix_ip_sport_len, 0, axis=0)
    print(matrix_ip_sport_len)
    print(matrix_ip_sport_len.shape)
    '''Save an array to a text file'''
    if index_file == 1:
        with open('141436_icmp_done_test.csv', 'w') as f:
            np.savetxt(f, matrix_ip_sport_len, delimiter=',', fmt='%d')  # ip_src,s_port,length,ip_dst,d_port,proto
    else:

        #saved_file= 'test'+ str(index_file)+'.csv'
        with open('141436_icmp_done_test.csv', 'a') as f:
            np.savetxt(f, matrix_ip_sport_len, delimiter=',', fmt='%d')  # ip_src,s_port,length,ip_dst,d_port,proto
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