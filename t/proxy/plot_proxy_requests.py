from matplotlib import pyplot as plt


with open("proxy_log_req") as file:
    proxy_values = []
    lines = file.readlines()
    for line in lines:
        requests = int(line.split()[1][1:])
        sec = float(line.split()[2])
        proxy_values += [(requests / sec) / 10**3]

with open("tcp_log_req") as file:
    tcp_values = []
    lines = file.readlines()
    for line in lines:
        requests = int(line.split()[1][1:])
        sec = float(line.split()[2])
        tcp_values += [(requests / sec) / 10**3]

with open("tcpls_log_req") as file:
    tcpls_values = []
    lines = file.readlines()
    for line in lines:
        requests = int(line.split()[1][1:])
        sec = float(line.split()[2])
        tcpls_values += [(requests / sec) / 10**3]

values = [tcp_values, tcpls_values, proxy_values]

fig = plt.figure()

plt.boxplot(values)

plt.xticks([1 , 2 , 3],labels=['tcp', 'tcpls', 'proxy'])

plt.ylabel('Request per second (khz)')

plt.show()