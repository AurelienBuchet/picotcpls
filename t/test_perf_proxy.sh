#!/bin/bash
while [ true ]
do
    ./../proxy_server -c assets/server.crt -k assets/server.key 10.100.0.2 4443
done