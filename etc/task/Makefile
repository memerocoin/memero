test-1:
	../../build/bin/wownerod \
--testnet \
--no-igd \
--hide-my-port \
--data-dir ./testnet/node_01 \
--p2p-bind-ip 127.0.0.1 \
--p2p-bind-port 40000 \
--rpc-bind-port 44000 \
--log-level 4 \
--add-exclusive-node 127.0.0.1:40001 \
# --fixed-difficulty 1000 \
# --add-exclusive-node 127.0.0.1:40002 \

test-2:
	../../build/bin/wownerod \
--testnet \
--no-igd \
--hide-my-port \
--data-dir ./testnet/node_02 \
--p2p-bind-ip 127.0.0.1 \
--p2p-bind-port 40001 \
--rpc-bind-port 44001 \
--log-level 1 \
--add-exclusive-node 127.0.0.1:40000 \
# --fixed-difficulty 1000 \

make-test-wallet:
	../../build/bin/wownero-wallet-cli --generate-new-wallet testnet/test1 --testnet \
--daemon-address 127.0.0.1:44000 \
--password ''

test-wallet:
	../../build/bin/wownero-wallet-cli --testnet --wallet-file testnet/test1 \
--daemon-address 127.0.0.1:44000 --log-level 4 \
--password ''

clear-test:
	@rm -rf testnet/node_01
	@rm -rf testnet/node_02
	@rm testnet/test1*
