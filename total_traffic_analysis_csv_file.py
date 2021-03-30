import time
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import csv
import numpy as np
from collections import defaultdict
import collections
from collections import Counter
import pandas as pd
'''Scatter 2D'''
def two_dimention_figure_port(a,b): #ports/s
    # MatplotLib
    plt.scatter(a, b,s=10)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("Ports/s")
    plt.title(name + " " + str(len(a)) + " IP")
    plt.show()
def two_dimention_figure_bytes_per_sec(a,b): #bytes per sec
    # MatplotLib
    plt.scatter(a, b,s=10)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("Bytes/s")
    plt.title(name + " " + str(len(a)) + " IP")
    plt.show()
def figure_of_fps_and_bps(a,b):
    # MatplotLib
    plt.scatter(a, b,s=10)  # Matplotlib
    plt.xlabel("Ports/s")
    plt.ylabel("Bytes/s")
    plt.title(name)
    plt.show()
def figure_of_ip_and_fps(a,b):
    #Matplotlib
    plt.scatter(a, b, s=10)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("Flow/s")
    plt.title(name)
    plt.show()

def packet_counter(pkt):
    count=Counter(pkt)
    temp= collections.OrderedDict(sorted((count.items())))
    return np.array(list(temp.values()))/300

def flow_counter(pkt):
    count= Counter(pkt)
    temp= collections.OrderedDict(sorted((count.items())))
    return np.array(list(temp.values()))
def figure_of_IP_and_packetpersec(a,b):   #packets/s
    # MatplotLib
    plt.scatter(a, b,s=10)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("Packets/s")
    #plt.title(name)
    plt.show()

def figure_of_Bytespersec_and_packetspersec(a,b):
    plt.scatter(a, b,s=10)  # Matplotlib
    plt.xlabel("Byte/s")
    plt.ylabel("Packets/s")
    #plt.title(name)
    plt.show()
'''Scatter 3d figure'''
def three_dimention_plot(a,b,c):
    fig = plt.figure()
    ax1 = fig.add_subplot(111, projection='3d')
    ax1.scatter(a, b, c, zdir='z', s=10, c=None, depthshade=True)
    ax1.set_xlabel('Bytes/s')
    ax1.set_ylabel('Ports/s')
    ax1.set_zlabel('IP')
    plt.title(name)
    plt.show()
'''Create a dictionary from 2 array and count total value in each key; a: key, b: value '''
def dict_from_2_list_and_cal_total_in_value(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    temp = {k: sum(v)/300 for k, v in temp.items()}  # Calculating the sum of all value in each key.
    temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp
'''Create a dictionary from 2 array a: key, b: value '''
def dict_from_2_list(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp
'''Open csv file'''
def open_csv_file(file_name):
    with open(file_name, mode='r') as f:
        loaded_file = np.loadtxt(f, delimiter=',', unpack=True)
    return loaded_file
#starting time
start=time.time()
#name='/home/mpec/PycharmProjects/dataset_new/test21-40.csv'
#name='/home/mpec/Tuan/plot_scatter_csv/Code/total_1h.csv'
#name='144436_icmp_done_test1.csv'
#name='/home/mpec/caida2007_to_victim/141436/141436_realTCP_done_test.csv'
name='/home/mpec/caida2007_to_victim/141436/141436_icmp_done_test.csv'
#loadtxt

#ip_address,pkt_len,s_port= open_csv_file(name)
#ip_address,pkt_len= open_csv_file(name)
#ip, d_port, s_port
df=pd.read_csv(name, sep=',',header=None)
print(len(df.values))
unique_rows = np.unique(df.values, axis=0)
print('Flow:', len(unique_rows))
print('Type:', type(unique_rows))
#ip_address= list(set(unique_rows[:,0]))
ip_address=df.iloc[:,0]
#d_port=list(set(unique_rows[:,1]))
#s_port=list(set(unique_rows[:,2]))
#pkt_len= list(set(unique_rows[:,1]))
pkt_len=df.iloc[:,1]
print(ip_address)
print("IP address: ", len(ip_address))
print("Type of IP adress: ", type(ip_address[0]))
print("pkt len: ", pkt_len)
'''Flow counter'''
#flows=flow_counter(ip_address)
#print(flows)
#print(len(flows))
'''Packet counter'''
pkts=packet_counter(ip_address)
'''
temp2= dict_from_2_list(ip_address,s_port)
s_port= list(temp2.values())
sport_slot=[]
for i in range(len(temp2)):
    counter= collections.Counter(s_port[i])
    sport_slot.append(len(counter.keys())/3600)
'''
#create default dictionary

temp1= dict_from_2_list_and_cal_total_in_value(ip_address,pkt_len)
#temp2= dict_from_2_list(ip_address,s_port)
#print(temp2)
#x= list(temp.keys())
print(temp1)
print(temp1.keys())
print("The number of keys: ", len(temp1))

'''
#total_value_dict = {k: sum(v) for k, v in res.items()}  # Calculating the sum of all value in each key.
ip_address= list(temp1.keys())
pkt_len=list(temp1.values())
#s_port= list(temp2.values())
'''
'''
sport_slot=[]
for i in range(len(temp2)):
    counter= collections.Counter(s_port[i])
    sport_slot.append(len(counter.keys())/3600)
'''
#print(ip_address)
#print(sport_slot)
'''3D plot'''
end=time.time()
print("Running time: ", end-start)
#figure_of_ip_and_fps(ip_address,flows)
#three_dimention_plot(pkt_len,sport_slot,ip_address)
two_dimention_figure_bytes_per_sec(temp1.keys(),temp1.values())
#two_dimention_figure_port(ip_address,sport_slot)
#figure_of_fps_and_bps(sport_slot,pkt_len)
#figure_of_Bytespersec_and_packetspersec(pkt_len,pkts)
#figure_of_IP_and_packetpersec(ip_address, pkts)
