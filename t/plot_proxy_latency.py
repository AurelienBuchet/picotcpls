from matplotlib import pyplot as plt

values = []

with open("proxy_log") as file:
    lines = file.readlines()
    for line in lines:
        values += int(line.split()[2])

fig = plt.figure()

plt.boxplot(values)