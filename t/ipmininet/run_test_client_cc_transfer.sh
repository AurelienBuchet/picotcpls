PORT=$1
GOODPUT=$2
V6=$3
V4=$4
./../../cli -t -x $GOODPUT -X -W 10 -T simple_transfer  -P $V6 $V4 $PORT

