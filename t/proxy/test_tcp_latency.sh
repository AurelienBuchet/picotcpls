#!/bin/bash
for i in {1..100}
do
   ./../../tcp_simple_client -t latency -4 10.100.0.1 8080 | grep latency >> tcp_log
done