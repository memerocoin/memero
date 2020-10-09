test-1:
	../../build/bin/lolnerod \
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
	../../build/bin/lolnerod \
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
	../../build/bin/lolnero-wallet-cli --generate-new-wallet testnet/test1 --testnet \
--daemon-address 127.0.0.1:44000 \
--password ''

test-wallet:
	../../build/bin/lolnero-wallet-cli --testnet --wallet-file testnet/test1 \
--daemon-address 127.0.0.1:44000 --log-level 4 \
--password ''

clear-test:
	@rm -rf testnet/node_01
	@rm -rf testnet/node_02
	@rm testnet/test1*


main-1:
	../../build/bin/lolnerod \
--no-igd \
--hide-my-port \
--data-dir ./mainnet/node_01 \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 127.0.0.1:41001 \

main-2:
	../../build/bin/lolnerod \
--no-igd \
--hide-my-port \
--data-dir ./mainnet/node_02 \
--p2p-bind-port 41001 \
--rpc-bind-port 45001 \
--log-level 1 \
--add-exclusive-node 127.0.0.1:41000 \

main-sync:
	@rm -rf mainnet/node_sync
	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/node_sync \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 10.0.0.1 \

make-main-wallet:
	../../build/bin/lolnero-wallet-cli --generate-new-wallet mainnet/test1  \
--daemon-address 127.0.0.1:45000 \
--password ''


main-wallet:
	../../build/bin/lolnero-wallet-cli --wallet-file mainnet/test1 \
--daemon-address 127.0.0.1:45000 --log-level 4 \
--password ''

clear-main:
	@rm -rf mainnet/node_01
	@rm -rf mainnet/node_02
	@rm mainnet/test1*
