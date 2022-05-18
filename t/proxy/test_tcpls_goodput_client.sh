#!/bin/bash
for i in {1..100}
do
    ./../../proxy_client -t goodput 10.100.0.2 4443 10.100.0.1 8080 | grep goodput >> tcpls_log_good
done