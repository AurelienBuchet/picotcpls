from matplotlib import pyplot as plt


plt.rcParams['font.size'] = 16

fig, axs = plt.subplots(3,1, sharex=True)
plt.xticks([1 , 2 , 3],labels=['tcp', 'tcpls', 'proxy'])


#plt.sca(axs)

index = 0

for name in ["800", "32K", "4M"]:


    with open("proxy_log_req" + "_" + name) as file:
        proxy_values = []
        lines = file.readlines()
        for line in lines:
            requests = int(line.split()[1][1:])
            sec = float(line.split()[2])
            proxy_values += [(requests / sec) / 10**3]

    with open("tcp_log_req" + "_" + name) as file:
        tcp_values = []
        lines = file.readlines()
        for line in lines:
            requests = int(line.split()[1][1:])
            sec = float(line.split()[2])
            tcp_values += [(requests / sec) / 10**3]

    with open("tcpls_log_req" + "_" + name) as file:
        tcpls_values = []
        lines = file.readlines()
        for line in lines:
            requests = int(line.split()[1][1:])
            sec = float(line.split()[2])
            tcpls_values += [(requests / sec) / 10**3]

    values = [tcp_values, tcpls_values, proxy_values]

    axs[index].boxplot(values)

    axs[index].set_title(name + "Bytes requests")
    index += 1

axs[1].set_ylabel('Request per second (khz)')

plt.sca(axs[2])

plt.xticks([1 , 2 , 3],labels=['tcp', 'tcpls', 'proxy'])


plt.show()