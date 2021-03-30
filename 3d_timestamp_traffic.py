import pandas as pd
import matplotlib.pyplot as plt
import time as tm   # time counter
import datetime as dt
import numpy as np
import csv
import ipaddress
from collections import Counter
from collections import defaultdict
import collections
from mpl_toolkits.mplot3d import Axes3D #3d plotting
import plotly.graph_objs as go
import plotly
'''Labeled data filtering '''
#l1: label
#l2: Source IP
#l3: Fw packets/s
#t4: Timestamp
def Anormally_and_benign_filtering(l1,l2,l3,l4):
    global benign_list, abnormally_list
    for i, j, k, t in zip(l1, l2, l3, l4):
        if i == 'Syn':
            abnormally_list = np.vstack([abnormally_list, [j, k, t]])
        else:
            benign_list = np.vstack([benign_list, [j, k, t]])
    benign_list = np.delete(benign_list, 0, axis=0)  # axis = 0, performing with rows, axis=1, performing with columns
    abnormally_list = np.delete(abnormally_list, 0, axis=0)
    #benign_list = np.transpose(benign_list, axes=None)
    #abnormally_list = np.transpose(abnormally_list, axes=None)
'''3D plotting'''
def Three_d_plotly(a1,b1,c1):
    print("Plotting...")
    fig = go.Figure(data=[go.Scatter3d(x=a1, y=b1, z=c1,mode='markers')])
    fig.update_layout(scene=dict(
        xaxis_title='X AXIS TITLE',
        yaxis_title='Y AXIS TITLE',
        zaxis_title='Z AXIS TITLE'))
    fig.show()
    #plotly.offline.iplot(fig, filename='simple-3d-scatter')
def three_dimention_plot(a1,b1,c1,a2,b2,c2):
    fig = plt.figure()
    ax1 = fig.add_subplot(111, projection='3d')
    ax1.scatter(a1, b1, c1, zdir='z', s=10, c='blue', depthshade=True)
    ax1.scatter(a2, b2, c2, zdir='z', s=10, c='red', depthshade=True)
    ax1.set_xlabel('IP')
    ax1.set_ylabel('Pkts/s')
    ax1.set_zlabel('Timestamp')
    plt.title('Traffic Diagram')
    plt.show()
def Two_dimention_plotly(a,b):
    print("Plotting...")
    fig = go.Figure()
    fig.add_trace(
        go.Scattergl(
            x=a,
            y=b,
            mode='markers',
            marker=dict(
                line=dict(
                    width=1,
                    color='DarkSlateGrey')
            )
        )
    )
    fig.update_layout(scene=dict(
        xaxis_title='IP',
        yaxis_title='Timestamp'))
    fig.show()
def Scatter_figure(a1,b1,a2,b2):
    # MatplotLib
    plt.scatter(a1, b1, color ='blue', s=10)  # Matplotlib
    plt.scatter(a2, b2, color ='red',s=10)  # Matplotlib
    plt.xlabel("IP")
    plt.ylabel("Packets/s")
    # plt.title(name)
    plt.show()
'''Label check'''
def Label_checking():
    print((Counter(Label)))
    print(Counter((Counter(Label))).keys())
    '''CSV Opening'''
def Open_csv_file(filename):
    with open(filename, mode='r') as f:
        loaded_file = np.loadtxt(f, unpack=True,skiprows=0)
    return loaded_file
def Ip_address_converter(a):
    for index in range(len(a)):
        a[index]=int(ipaddress.ip_address(a[index]))
    return a
def Time_to_int_number(time_stamp):
    s = pd.Series(time_stamp)
    new_time_stamp = pd.to_datetime(s).dt.round('H').dt.strftime('%m%d%H')
    new_time_stamp = new_time_stamp.to_numpy()
    new_time_stamp= new_time_stamp.astype(np.int)
    '''Optional section'''
    #new_time_stamp =new_time_stamp-np.amin(new_time_stamp)
    '''Upper part is optional'''
    return new_time_stamp
def Dict_from_2_list(a,b):
    temp= defaultdict(set)
    for delvt, pin in zip(a, b):
        temp[delvt].add(pin)
    #temp = collections.OrderedDict(sorted(temp.items()))        # SORT kEY FROM LOW TO HIGH
    return temp
#fields=['Source IP', 'Source Port']
'''Pandas read_csv'''
chunk_size=1000
#file_name= 'Syn.csv'
file_name='/home/mpec/PycharmProjects/dataset_new/venv/Syn.csv'
data= pd.read_csv(file_name,chunksize=chunk_size,skipinitialspace=True, usecols= None,index_col=None)
pd.set_option('display.expand_frame_repr',False)        #expanding the full output screen mode in order to display all columns
pd.options.display.max_columns = None
#pd.set_option('display.max_rows', None)
data=pd.concat(data)
print(data)
'''Pandas read_csv done'''
DestIP=data['Destination IP'].to_numpy()
SrcIP=data['Source IP'].to_numpy()
print(Counter(data['Destination IP'].to_numpy()))
print(Counter(data['Protocol'].to_numpy()))
Label= data['Label'].to_numpy()

FW_pkts_per_sec= data['Fwd Packets/s'].to_numpy()
print('pkts/s type: ',type(FW_pkts_per_sec[0]))
Time_stamp= data['Timestamp'].to_numpy()
''' Dictionary{ Label: "SrcIP" }'''
new_dict= Dict_from_2_list(Label,SrcIP)
print(len(new_dict))
print(type(new_dict))
print(dict(new_dict)['Syn'])

'''Convert ip address to decimal form'''
SrcIP=Ip_address_converter(SrcIP)
print('Source IP: \n ',SrcIP)
DestIP=Ip_address_converter(DestIP)
print('Destination IP \n:',DestIP)
'''Convert timestamp to integer'''
Time_stamp=Time_to_int_number(Time_stamp)
print('Time stamp: ',Time_stamp)
#three_dimention_plot(SrcIP,FW_pkts_per_sec,Time_stamp1)
#Three_d_plotly(SrcIP,FW_pkts_per_sec,Time_stamp1)
#Two_dimention_plotly(SrcIP,Time_stamp)
#Scatter_figure(Time_stamp,SrcIP)
benign_list=np.empty([1,3])             # benign list initializing
abnormally_list=np.empty([1,3])         # abnormally list initializing

'''Label filtering'''
#Anormally_and_benign_filtering(Label,SrcIP,FW_pkts_per_sec,Time_stamp)
#print("Benign: \n", benign_list[0])
#print("Abnormal:  \n", abnormally_list[0])
#three_dimention_plot(benign_list[0],benign_list[1],benign_list[2],abnormally_list[0],abnormally_list[1],abnormally_list[2])
'''Benign list and Anormally list extracting'''
#Anormally_and_benign_filtering(Label,SrcIP,FW_pkts_per_sec,Time_stamp)
#print("Benign list: ", benign_list[0])

#print("Abnormally list: ", abnormally_list[0])
'''Save to csv'''
#with open('syn_label.csv', 'w') as f:
#    np.loadtxt(f, abnormally_list, delimiter=',', fmt='%d')
#with open('benign.csv','w') as f:
#    np.loadtxt(f, benign_list, delimiter=',',fmt='%d')
#print("Benign list: ", benign_list)
#print("Abnormally list: ", abnormally_list)
'''
timestamp= data['Timestamp'].to_numpy()
for sub_time in timestamp:
    print('Timestamp type: ', type(sub_time), sub_time)

time_integer_number= time_to_int_number(timestamp)
time_integer_number=time_integer_number.to_numpy()
time_integer_number=time_integer_number.astype(np.float)  /1000  #convert string numpy array to float 64 numpy array
for time1 in time_integer_number:
    print("type: ",type(time1),time1)
print(time_integer_number)


#time.mktime(datetime.datetime.strptime(s, "%d/%m/%Y").timetuple())
#different_date_string = dt.datetime.strftime(date_string, '%m%d%H')
#different_date= dt.datetime.strftime(timestamp,'%m%d%H')
#timestamp_new = int(time.mktime(datetime.now().timetuple()))
#timestamp_new=int(tm.mktime(timestamp[0].timetupple()))
a=data['Source IP'].to_numpy()                          #convert dataframe to numpy array
b=data['Destination IP'].to_numpy()
print("Type of data data['Source IP']", type(a))
internet_protocol=ip_address_converter(a)
print("IP's Decimal form:", internet_protocol)
end= tm.time()
print("Executing time:", end-start)
'''

