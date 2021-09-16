CHANGE_CC=$1
LIMIT_CC=$2
./run_test_server_cc_transfer.sh 4444 $CHANGE_CC $LIMIT_CC fc00:0:5::2 192.168.5.100 test_cc_s2.data server2
