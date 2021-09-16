PORT=$1
CHANGE_CC=$2
LIMIT_CC=$3
V6=$4
V4=$5
FILE_TO_SEND=$6
GOODPUT_FILE=$7
truncate -s 2G $FILE_TO_SEND

if [ $CHANGE_CC -eq 1 ]
then
     ./../../cli -t -r -w $LIMIT_CC -m bpf_cubic.o -j bpf_cubic  -g plot.log -T simple_transfer -i $FILE_TO_SEND -k ../assets/server.key -c ../assets/server.crt -Z $V6 $V4 $PORT
else
     ./../../cli -t -m bpf_cubic.o -j bpf_cubic  -x $GOODPUT_FILE -W 10  -T simple_transfer -i $FILE_TO_SEND -k ../assets/server.key -c ../assets/server.crt -Z $V6 $V4 $PORT
fi
