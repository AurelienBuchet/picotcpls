import matplotlib.pyplot as plt
import sys
filepath1 = sys.argv[1]
filepath2 = sys.argv[2]
cc1 = sys.argv[3]
cc2 = sys.argv[4]
bw = sys.argv[5]
delay = sys.argv[6]
with open(filepath1, 'r') as f:
    lines = f.readlines()
    x = [float(line.split()[0]) for line in lines]
    y = [float(line.split()[1]) for line in lines]
with open(filepath2, 'r') as f:
    lines = f.readlines()
    x1 = [float(line.split()[0]) for line in lines]
    y1 = [float(line.split()[1]) for line in lines]
plt.xlabel('Time (s)')
plt.ylabel('Goodput (Mbps)')
plt.title(bw + 'Mbps, delay ' + delay + 'ms' )
vegas, bpf_cubic, = plt.plot(x ,y, x1, y1)
plt.legend([vegas, (vegas, bpf_cubic)], [ cc1, cc2])
plt.annotate('injection of bpf_cubic', xy=(117.561356,  12.116826),  xycoords='data',
            xytext=(192, 29), textcoords='data',
            arrowprops=dict(arrowstyle="->",
                            connectionstyle="arc3"))

plt.show()
