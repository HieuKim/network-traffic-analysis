#import pyshark
from scapy.all import*
from collections import Counter
import matplotlib.pyplot as plt
from collections import defaultdict
import ipaddress
import csv
import numpy as np
import subprocess as sub
def mat_plot2d_figure(a,b):
    # MatplotLib
    plt.scatter(a, b)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("The number of ports")
    plt.title(file_name + " " + str(len(a)) + " IP")
    plt.show()
def packet_counter(pkt):
    count=Counter(pkt)
    temp= collections.OrderedDict(sorted((count.items())))
    return np.array(list(temp.values()))
def Dict_from_2_list(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    #temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp
def dict_from_2_list_and_cal_total_in_value(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    temp = {k: sum(v) for k, v in temp.items()}  # Calculating the sum of all value in each key.
    temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp
#import numpy as np
#file_name= '/home/hieu/Desktop/ddostrace.to-victim.20070804_140436.pcap'
#file_name='/home/hieu/Desktop/pcap_normal/lab_3_edit_00000_20m_00002_20200213103450_2.pcap'
#file_name='/home/mpec/caida2007_to_victim/141936_tcp_done_icmp/test150.pcap'
#file_name='/home/mpec/data_set_python/lab_3_edit_00000_20m_00002_20200213103450_1.pcap'
file_name='/media/mpec/eb38a860-81a7-43f8-9205-6df6e098435f/income/inC_367_file0'
#name='lab_3_edit_00000_20m_00002_20200213103450_1.pcap'
#myfilter='tcp and tcp.flags.syn 1 and tcp.flags.ack 0'
#myfilter1='tcp and tcp.flags.syn==1'
#b= sniff(offline= file_name,filter=myfilter)
#b= sniff(offline= file_name, filter='tcp[tcpflags] & tcp-ack != 0') # filter tcp ack packets
b= sniff(offline= file_name)
#tcp_ip_src=[]
#ip_decimal=[]
#print(b.summary())
#print(len(b))
#print(len(pkt))
#print(b[0].show())
#print(b(IP(dst="71.126.222.64")/TCP(flags="S")))
#print(len(b))
matrix_ip = np.empty([1,2])
print(matrix_ip)
for j in b:
    #if j.haslayer(IP)==1 and  hasattr(j, 'sport') :
    if j.haslayer(IP)==1:
        #X.append(j['IP'].src)
        matrix_ip=np.vstack([matrix_ip,[int(ipaddress.ip_address(j['IP'].src)),j['IP'].len]])
        #X.append(j.srt)
matrix_ip = np.delete(matrix_ip, 0, axis=0)
#unique,counts =np.unique(matrix_ip, return_counts=True)
#unique_counts= np.column_stack([unique,counts])
'''Cal total packet length'''
#print('matrix ip 2 \n:',matrix_ip[:,0])
#print('matrix ip 1 \n:',matrix_ip[:,1])
#print(matrix_ip[:,0].shape)
newdic =dict_from_2_list_and_cal_total_in_value(matrix_ip[:,0],matrix_ip[:,1])
print(newdic)
Ip_list=np.array(list(newdic.keys()))
Pkt_len=np.array(list(newdic.values()))
Ip_Len_Array= np.vstack([Ip_list,Pkt_len])
Ip_Len_Array= np.transpose(Ip_Len_Array,axes=None)
print(Ip_Len_Array)
print('Shape:',Ip_Len_Array.shape)
#print(Ip_Len_Array[0,1])
with open('Outgoing367_test.csv','w') as f:
    np.savetxt(f,Ip_Len_Array,delimiter=',', fmt='%d')
#print(type(dic))
#print('Outgoing: ',dic)
'''
res= defaultdict(list)
for i,j in zip(ip_decimal,s_port):
    res[i].append(j)
print("Sport: ",type(res))
lists= sorted(res.items())                          # sorted by key, return a list of tuples
print("list: ",lists)
ip_decimal, s_port= zip(*lists)                     #unpack a list of pairs into 2 tuples

for i in range(len(ip_decimal)):                    # Filtering identical ports and count and append the number of occurences
    counter = collections.Counter(s_port[i])        # to a list dport[]
    port_number.append(len(list(counter.keys())))   # number of ports
print("slot: ",port_number)
print("IP:",len(ip_decimal))
'''


