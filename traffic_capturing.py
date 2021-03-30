from scapy.all import sniff
import time
import csv
import ipaddress
import collections
start1= time.time()
def make1D(data):                               # 2D-> 1D conversion function
    returned=[]
    for x in data:
        returned += x
    return returned
tcp_ip_src = []
tcp_ip_dst = []
tcp_src_nondecimal = []
# print(b[0].show())
port_number = []
sport = []
b= sniff(filter='tcp', timeout=60)
for j in b:
    if j['IP'].src not in tcp_src_nondecimal:
        tcp_ip_src.append(int(ipaddress.ip_address(j['IP'].src)))
        tcp_src_nondecimal.append(j['IP'].src)
        tcp_ip_dst.append(int(ipaddress.ip_address(j['IP'].dst)))
trix_port = [[0 for i in range(0)] for j in range(len(tcp_ip_src))]  # 2D array for port
matrix_ip = [[0 for i in range(0)] for j in range(len(tcp_ip_src))]  # 2D array for ip

for j in range(len(tcp_ip_src)):  # appendding TCP IP to a matrix
    for i in b:
        if tcp_src_nondecimal[j] == i['IP'].src:
            # trix_port[j].append(int(ipaddress.ip_address(j['IP'].src)))
            trix_port[j].append(i['TCP'].sport)

# print("Matrix Port: ", trix_port)
for i in range(len(tcp_ip_src)):  # Filtering identical ports and count and append the number of occurences
    counter = collections.Counter(trix_port[i])  # to a list sport[]
    sport.append(len(counter.keys()))  # Port counter appending to sport list
    port_number.append(list(counter.keys()))  # Port name appending to port_number list
    # print("# ", i, len(counter.keys()), list(counter.keys()))
    for j in range(len(counter.keys())):
        matrix_ip[i].append(tcp_ip_src[i])  # Appending IP to the list matrix_ip list
        '''
print("Source IP: ", len(tcp_ip_src), tcp_ip_src)
print("Dest IP: ", len(tcp_ip_dst), tcp_ip_dst)
print("The number of ports: ", sport)
print("Port number: ", port_number)
print("IP matrix: ", matrix_ip)
print("Estimated line for CSV: ", sum(sport))
print(" port_number 2D -> 1D processing: ", make1D(port_number))
print("IP matrix 2D -> 1D processing:", make1D(matrix_ip))
'''
matrix_for_csv = [[0 for i in range(0)] for j in range(sum(sport))]  # 2D list exporting to csv file
for i in range(sum(sport)):  # Transfer to 1 row IP and port to a 2d list for csv file
    matrix_for_csv[i].append(make1D(matrix_ip)[i])
    matrix_for_csv[i].append(make1D(port_number)[i])
with open('tcp_sniff_test1.csv', 'w', newline="") as f:  # Exporting to test.csv
    # fieldnames=['IP', 'Port_number']
    thewriter = csv.writer((f))
    for i in range(len(matrix_for_csv)):
        thewriter.writerow(matrix_for_csv[i])
end= time.time()
print("Processed time:", end-start1)