## Description

This test aims to show the  use case where one flow starts with vegas as congestion controller. Later a second flow is started with cubic as congestion controller. As cubic is more aggressive the second flow will get most of the available bandwidth. When the server of the first flow detect the bandwidth decreasing, it injects bpf_cubic congestion controller and fairness is established. 

## Install required softwares and libraries

```bash
sudo apt install mininet
sudo pip3 install mininet
sudo apt install openvswitch-testcontroller
sudo ln -s /usr/bin/ovs-testcontroller /usr/bin/controller
sudo fuser -k 6653/tcp
sudo apt install libssl-dev
sudo pip3 install matplotlib
```

## Clone the repo and switch to tcpls/ebpf-cc branch

```
git clone git@github.com:pluginized-protocols/picotcpls.git
cd picotcpls
git checkout tcpls/bpf-cc
```

## Launch mininet script to execute the test

delay = 60ms, bw = 100Mbps, jitter = 0% and loss = 0%

```bash
cd t/ipmininet
sudo python3 topo-for-test-ebpf-cc.py 60 100 0 0
```

The generated logs are here /tmp/{s1,s2,server1,server2}.log

## Plot the graphic

```bash
python3 plot_goodput.py /tmp/server2.log /tmp/server1.log  cubic vegas_bpf_cubic 100 60
```
