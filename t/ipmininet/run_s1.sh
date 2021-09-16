CHANGE_CC=$1
LIMIT_CC=$2
./run_test_server_cc_transfer.sh 4443 $CHANGE_CC $LIMIT_CC fc00:0:3::2 192.168.3.100 test_cc_s1.data server1
