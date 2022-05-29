#!/bin/bash
for i in {1..100}
do
   if [ $1 -eq 1 ]
   then
        ./../../proxy_server -c ../assets/server.crt -k ../assets/server.key -t goodput 10.100.0.2 4443
    elif [ $1 -eq 2 ]
    then
        ./../../proxy_server -c ../assets/server.crt -k ../assets/server.key -v -t requests -r $2 10.100.0.2 4443
    else
        ./../../proxy_server -c ../assets/server.crt -k ../assets/server.key 10.100.0.2 4443
    fi
done