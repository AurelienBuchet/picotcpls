#!/bin/bash
for i in {1..100}
do
   ./../../tcp_simple_client -4 -t requests 10.100.0.1 8080 | grep requests >> tcp_log_req
done