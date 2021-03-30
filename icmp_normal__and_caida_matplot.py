from scapy.all import*
#from scapy import*
import matplotlib.pyplot as plt
import numpy as np
import csv
import ipaddress
from collections import defaultdict
from operator import itemgetter
#file_name= '/home/hieu/Desktop/ddostrace.to-victim.20070804_140436.pcap'
#file_name='/home/hieu/Desktop/pcap_analysis/test282.pcap'
file_name='/home/mpec/data_set_python/lab_3_edit_00000_20m_00002_20200213103450_1.pcap'
#file_name='/home/data_set_python/lab_3_edit_00000_20m_00002_20200213103450.pcap'
name='lab_3_edit_00000_20m_00002_20200213103450_1.pcap'
#pkts= rdpcap(file_name)
a= sniff(offline= file_name)
#a= sniff(offline= file_name,filter='icmp')
#a=rdpcap(file_name)
#print("ICMP packets: ", len(a))
print("packets: ", len(a))
#print(a[1307].show())
#dura_tion= pkts[-1].time-pkts[0].time     # Duration of the whole pcap file
#dura_tion=1
#icmp_ip_unfilter=[]
#icmp_packet_unfilter=[]
icmp_ip=[]
ip_decimal=[]
pack_per_sec1=[]
for j in range(len(a)):
    if a[j].haslayer(IP)==1:
        icmp_ip.append((a[j]['IP'].src))
        ip_decimal.append(int(ipaddress.ip_address(a[j]['IP'].src)))
        pack_per_sec1.append((a[j]['IP'].len)/300)
'''Creating a dictionary with key = IP &  value = bytes/s '''
res= defaultdict(list)
for i, j in zip(ip_decimal,pack_per_sec1):
    res[i].append(j)
print("Bytes/s: ",res.values())
total_value_dict={k: sum(v) for k, v in res.items()}        # Calculating the sum of all value in each key.
print("Total value dict\n",total_value_dict)
'''for j in a:
    if j['IP'].src not in icmp_ip:
        icmp_ip.append(j['IP'].src)                               # icmp filter
    icmp_ip_unfilter.append((j['IP'].src))                       # A list including all the ip address wihtout filtering
    icmp_packet_unfilter.append(j['IP'].len)   '''                  # A list including all the packet length without summing them

'''Calculate the avg the packet length and insert to a list '''
'''for val in icmp_ip:
    total = 0.0
    for index, value in enumerate(icmp_ip_unfilter):
        if val== value:
            total = total + icmp_packet_unfilter[index]/300
    pack_per_sec.append(total)'''
'''Calculate the avg the packet length and insert to a list '''
lists = sorted(total_value_dict.items())                    # sorted by key, return a list of tuples
print("lists: ",lists)
ip_decimal,pack_per_sec1= zip(*lists)                                            #unpack a list of pairs into 2 tuples
print("ip_src: ",len(ip_decimal),ip_decimal)
print("bytes/s:",len(pack_per_sec1),pack_per_sec1)

#print("IP: ", icmp_ip)
#print("the number of IP: ", len(icmp_ip))

#print("ICMP IP slots: ", len(icmp_ip))
#print('ICMP IP:',icmp_ip)
#print("bytes/s: ", pack_per_sec)
#matrix_for_csv= np.vstack((icmp_ip,pack_per_sec)).T                        #transpose to export to csv file
print("Exporting to CSV...")
'''with open('test_icmp.csv', 'a', newline="") as f:                        #Exporting to icmp_analysis.csv
    thewriter= csv.writer(f)
    for i in range(len(matrix_for_csv)):
        thewriter.writerow(matrix_for_csv[i])'''
print("Process completed!!!")
with open('icmp_analysis_141436.csv','r') as csv_file:
    csv_reader= csv.reader(csv_file)
    arr=[]
    for line in csv_reader:
        #print(line)
        arr.append(line)
print(len(arr))
x_array=np.transpose(arr)
#icmp_ip_src= x_array[0]                      # x_array[0]= unfiltered ip list
#counter= collections.Counter(icmp_ip_src)
#icmp_ip_src=(list(counter.keys()))
#occurence= list(counter.values())
#print("Unique IP:\n", len(icmp_ip_src), icmp_ip_src)
#print("Packets in each IP:\n", occurence)
x_arr=[]
#x = np.array(x_array[1])                    # x: array of bytes/s
#arr_pks = x.astype(np.float)            # Convert string array to float array
arr_pks=np.array([v.replace(',', '') for v in x_array[1]], dtype=np.float32)            # Convert string array x to float array x
for i in x_array[0]:
    x_arr.append(int(ipaddress.ip_address(i)))
#print(type(icmp_ip_src))
#print(type(arr_pks))
print((arr_pks))
#print(sum(arr_pks))
'''Creating a dictionary with key = IP &  value = bytes/s '''
res= defaultdict(list)
for i, j in zip(x_arr,arr_pks):
    res[i].append(j)
print("Bytes/s: ",res.values())
'''*********************************************************** '''
total_value_dict={k: sum(v) for k, v in res.items()}        # Calculating the sum of all value in each key.
print("Total value dict\n",total_value_dict)
'''N largest values in dictionary and their key using 'from operator import itemgetter ' '''
# N largest values in dictionary
# Using sorted() + itemgetter() + items()
N = 5
res = dict(sorted(total_value_dict.items(), key=itemgetter(1), reverse=True)[:N])
# printing result
print("The top 5 value pairs are  " + str(res))
'''************************************************************************************'''

'''         # N largest values in dictionary and their key using 'from heapq import nlargest '
N=5
res = nlargest(N, total_value_dict, key = total_value_dict.get)
print("The top 5 value pairs are  " + str(res))
'''
lists = sorted(total_value_dict.items())                    # sorted by key, return a list of tuples
print("lists: ",lists)

icmp_ip,pack_per_sec= zip(*lists)                                            #unpack a list of pairs into 2 tuples
print("icmp_ip_src: ",len(icmp_ip),icmp_ip)
print("pack_per_sec:",len(pack_per_sec),pack_per_sec)

#print("Unique IP: ", len(icmp_ip_src), icmp_ip_src)
#print("Bytes/s :", len(pack_per_sec), pack_per_sec)                                    # bytes/s
'''************************************************************'''
#MatplotLib

print("MatplotLib Processing...")
plt.scatter(icmp_ip,pack_per_sec,color='red',marker="s",label='Caida '+ str(len(icmp_ip))+' IP')
plt.scatter(ip_decimal,pack_per_sec1,color='blue',marker="o",label='Norm '+ str(len(ip_decimal))+' IP')# Matplotlib
plt.xlabel("IP")
plt.ylabel("Bytes/s")
#plt.title("Ddostrace.to-victim.20070804_144936 "+ str(len(icmp_ip))+" IP")
plt.title("Caida 2007 141436 and Normal traffic")
plt.legend(loc='upper left');
plt.show()
print("Done")
#MatplotLib


