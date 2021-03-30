# doc csv file
from scapy.all import *
import ipaddress
import csv
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from collections import Counter
import collections
file_name='/home/mpec/data_set_python/lab_3_edit_00000_20m_00002_20200213103450_1.pcap'
name='lab_3_edit_00000_20m_00002_20200213103450_1.pcap'

#b= sniff(offline= file_name,filter='tcp')
b= sniff(offline= file_name)
tcp_ip_src=[]
ip_decimal=[]
#tcp_ip_dst=[]
print(b[0].show())
port_number=[]
s_port=[]
for j in b:
    if j.haslayer(IP)==1 and  hasattr(j, 'sport') :
        tcp_ip_src.append(j['IP'].src)
        ip_decimal.append(int(ipaddress.ip_address(j['IP'].src)))
        s_port.append(j.sport)
res= defaultdict(list)
for i,j in zip(ip_decimal,s_port):
    res[i].append(j)
print("Sport: ",type(res))
lists= sorted(res.items())                          # sorted by key, return a list of tuples
print("list: ",lists)
ip_decimal, s_port= zip(*lists)                     #unpack a list of pairs into 2 tuples
#print("ip_src: ",len(tcp_ip_src),tcp_ip_src)
#print("p:",len(s_port),s_port)
for i in range(len(ip_decimal)):                    # Filtering identical ports and count and append the number of occurences
    counter = collections.Counter(s_port[i])        # to a list dport[]
    port_number.append(len(list(counter.keys())))   # number of ports
print("slot: ",port_number)
print("IP:",len(ip_decimal))
#filename_input="input.csv"
#filename_output="output.csv"
# Open the input_file in read mode and output_file in write mode
with open('tcp_analysis_20070804_142936.csv','r') as csv_file:
    csv_reader= csv.reader(csv_file)
    arr=[]
    for line in csv_reader:
        #print(line)
        arr.append(line)
print(len(arr))

x_array=np.transpose(arr)
#tcp_ip_src=np.array([v.replace(',', '') for v in x_array[1]], dtype=np.float32)  # Convert string array x to float array x
#arr_port=np.array([v.replace(',', '') for v in x_array[1]], dtype=np.float32)  # Convert string array x to float array x
tcp_ip_src = list(map(int, x_array[0]))                  # transfer string to int and put into tcp ip list
arr_port=list(map(int, x_array[1]))                      # transfer string to int and put into arr_port list
'''Creating a dictionary with key = IP &  value = port number '''
res= defaultdict(list)
for i, j in zip(tcp_ip_src,arr_port):
    res[i].append(j)
print("IP: ", res.keys())
print("Flow/s: ",res.values())
arr_port.clear()
for key, value in res.items():
    #print value
    #print(key, len([item for item in value if item]))
    #print(key, len(list(filter(bool, value))))         # Print key and the number of its values
    arr_port.append(len(list(filter(bool, value))))
tcp_ip_src=list(res.keys())                             # tcp ip list: individually
arr_port=list(res.values())                             # port list:  all
port_slot=[]                                            # count the occurrence of each port
for i in range(len(tcp_ip_src)):
    counter= collections.Counter(arr_port[i])           #count the occurrence of each port: preperation
    port_slot.append(len(counter.keys()))               #count and append to port_slot
print("IP: ", tcp_ip_src)
print("Flow/s: ",arr_port)
print("port numbers: ", port_slot)
arr_port.clear()
res.clear()
'''Creating a dictionary with key = IP &  value = flow/s  '''
res= defaultdict(list)
for i, j in zip(tcp_ip_src,port_slot):
    res[i].append(j)

print("IP: ", res.keys())
print("Flow/s: ",res.values())

lists = sorted(res.items())                             # sorted by key, return a list of tuples from low to high value
print("lists: ",lists)
tcp_ip_src,arr_port= zip(*lists)                        # extract into 2 tuples
print(tcp_ip_src)
print(arr_port)



#MatplotLib
print("MatplotLib Processing...")
plt.scatter(tcp_ip_src,arr_port,color='red',marker="s",label='Caida '+ str(len(tcp_ip_src))+' IP')
plt.scatter(ip_decimal,port_number,color='blue',marker="o",label='Norm '+ str(len(ip_decimal))+' IP')
plt.xlabel("IP")
plt.ylabel("The number of ports")
plt.title("TCP caida 142936 and normal traffic ")
plt.legend(loc='upper left');
plt.show()
print("Done")