#!/bin/bash
for i in {1..100}
do
   ./../../tcp_simple_client -t goodput -4 10.100.0.1 8080 | grep goodput >> tcp_log_good
done