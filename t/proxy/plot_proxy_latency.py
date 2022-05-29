from matplotlib import pyplot as plt
import numpy as np

with open("proxy_log") as file:
    proxy_values = []
    lines = file.readlines()
    for line in lines:
        proxy_values += [float(line.split()[2]) * 1000]

with open("tcp_log") as file:
    tcp_values = []
    lines = file.readlines()
    for line in lines:
        tcp_values += [float(line.split()[2]) * 1000]

with open("tcpls_log") as file:
    tcpls_values = []
    lines = file.readlines()
    for line in lines:
        tcpls_values += [float(line.split()[2]) * 1000]

tcp_tcpls = np.array(tcp_values) + np.array(tcpls_values)

values = [tcp_values, tcpls_values, proxy_values, tcp_tcpls]

plt.rcParams['font.size'] = 20


fig = plt.figure()

plt.boxplot(values)

plt.xticks([1 , 2 , 3, 4],labels=['tcp', 'tcpls', 'proxy', 'tcp+tcpls'])

plt.ylabel('Latency (msec)')

plt.show()