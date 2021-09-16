PORT=$1
V6=$2
V4=$3
FILE_TO_SEND=$4
GOODPUT_FILE=$5
truncate -s 2G $FILE_TO_SEND

./../../cli -t -m bpf_cubic.o -j bpf_cubic  -x $GOODPUT_FILE -W 20 -X -R 48 -T simple_transfer -i $FILE_TO_SEND -k ../assets/server.key -c ../assets/server.crt -Z $V6 $V4 $PORT

