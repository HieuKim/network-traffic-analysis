import csv
import numpy as np
import matplotlib.pyplot as plt
#from collections import Counter
from collections import defaultdict
#from heapq import nlargest
from operator import itemgetter
import ipaddress
import collections
def mat_plot:
    print("MatplotLib Processing...")
    plt.scatter(icmp_ip, pack_per_sec)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("Bytes/s")
    plt.title("Ddostrace.to-victim.20070804_144936 " + str(len(icmp_ip)) + " IP")
    plt.show()
    print("Done")
#filename_input="input.csv"
#filename_output="output.csv"
# Open the input_file in read mode and output_file in write mode
with open('icmp_analysis_finale.csv','r') as csv_file:
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
plt.scatter(icmp_ip,pack_per_sec)                                         # Matplotlib
plt.xlabel("IP")
plt.ylabel("Bytes/s")
plt.title("Ddostrace.to-victim.20070804_144936 "+ str(len(icmp_ip))+" IP")
plt.show()
print("Done")
