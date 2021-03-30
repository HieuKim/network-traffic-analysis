# doc csv file
import csv
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from collections import Counter
import collections
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

plt.scatter(tcp_ip_src,arr_port)                                         # Matplotlib
plt.xlabel("IP")
plt.ylabel("The number of ports")
plt.title("Ddostrace.to-victim.20070804_142936   " + str(len(tcp_ip_src)) + 'IP')
plt.show()
