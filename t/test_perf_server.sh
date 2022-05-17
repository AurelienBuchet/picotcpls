#!/bin/bash
for i in {1..100}
do
   ./../tcp_simple_server -4 10.100.0.1 8080 > /dev/null
done