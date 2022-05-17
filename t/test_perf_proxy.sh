#!/bin/bash
for i in {1..100}
do
    ./../proxy_server -c assets/server.crt -k assets/server.key 10.100.0.2 4443
done