from sys import float_repr_style
from matplotlib import pyplot as plt


with open("proxy_log_good") as file:
    proxy_values = []
    lines = file.readlines()
    for line in lines:
        bytes = int(line.split()[1][1:])
        sec = float(line.split()[3])
        proxy_values += [(bytes * 8/ sec) / 10**9]

with open("tcp_log_good") as file:
    tcp_values = []
    lines = file.readlines()
    for line in lines:
        bytes = int(line.split()[1][1:])
        sec = float(line.split()[3])
        tcp_values += [(bytes * 8 / sec) / 10**9]

with open("tcpls_log_good") as file:
    tcpls_values = []
    lines = file.readlines()
    for line in lines:
        bytes = int(line.split()[1][1:])
        sec = float(line.split()[3])
        tcpls_values += [(bytes * 8 / sec) / 10**9]

values = [ tcp_values,tcpls_values, proxy_values]

plt.rcParams['font.size'] = 20

fig = plt.figure()

plt.boxplot(values)

plt.xticks([1 , 2 , 3],labels=['tcp', 'tcpls', 'proxy'])

plt.ylabel('goodput (Gbits/sec)')

plt.show()