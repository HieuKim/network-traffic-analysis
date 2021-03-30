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
def dict_from_2_list_and_cal_total_in_value(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    temp = {k: sum(v) for k, v in temp.items()}  # Calculating the sum of all value in each key.
    temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp