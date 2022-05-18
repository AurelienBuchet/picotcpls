#!/bin/bash
for i in {1..100}
do
   if [ $1 -eq 1 ]
   then
      ./../../tcp_simple_server -s -4 10.100.0.1 8080 > /dev/null
   elif [ $1 -eq 2 ]
   then
      ./../../tcp_simple_server -r -4 10.100.0.1 8080 > /dev/null
   else
      ./../../tcp_simple_server -4 10.100.0.1 8080 > /dev/null
   fi
done