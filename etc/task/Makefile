test-1:
	../../build/bin/lolnerod \
--testnet \
--hide-my-port \
--data-dir ./testnet/node_01 \
--p2p-bind-ip 127.0.0.1 \
--p2p-bind-port 40000 \
--rpc-bind-port 44000 \
--log-level 1 \
--add-exclusive-node 127.0.0.1:40001 \
--fixed-difficulty 1000 \
# --add-exclusive-node 127.0.0.1:40002 \

test-2:
	../../build/bin/lolnerod \
--testnet \
--hide-my-port \
--data-dir ./testnet/node_02 \
--p2p-bind-ip 127.0.0.1 \
--p2p-bind-port 40001 \
--rpc-bind-port 44001 \
--log-level 1 \
--add-exclusive-node 127.0.0.1:40000 \
--fixed-difficulty 1000 \

test-1-mining:
	../../build/bin/lolnerod \
--testnet \
--hide-my-port \
--data-dir ./testnet/node_01 \
--p2p-bind-ip 127.0.0.1 \
--p2p-bind-port 40000 \
--rpc-bind-port 44000 \
--add-exclusive-node 127.0.0.1:40001 \
--fixed-difficulty 1000 \
--start-mining hpAhTqFSj91LL7FHxT6yUScBDBfA5bfiMAmC6A3KHBZc1jGv5t5LJMELYoFNjeNPoMJNeSnBiK9WmKNqxXsj9rWn1iNFeiTna

test-2-mining:
	../../build/bin/lolnerod \
--testnet \
--hide-my-port \
--data-dir ./testnet/node_02 \
--p2p-bind-ip 127.0.0.1 \
--p2p-bind-port 40001 \
--rpc-bind-port 44001 \
--add-exclusive-node 127.0.0.1:40000 \
--fixed-difficulty 1000 \
--start-mining hp9PEj54frgDUiAkSTsnmJXxoN2gengwfdg2RGThzUEo2ycy1bVvVMXf1nY2KMiGwzVkSGBR8KRd8LbSRYb6eny62DwZFVeyP

make-test-wallet:
	../../build/bin/lolnero --new testnet/test1 --testnet \
--daemon-address 127.0.0.1:44000 \
--password ''

make-test-wallet-2:
	../../build/bin/lolnero --new testnet/test2 --testnet \
--daemon-address 127.0.0.1:44001 \
--password ''

test-wallet:
	../../build/bin/lolnero --testnet --open testnet/test1 \
--daemon-address 127.0.0.1:44000 --log-level 1 \
--password ''

test-wallet-2:
	../../build/bin/lolnero --testnet --open testnet/test2 \
--daemon-address 127.0.0.1:44001 --log-level 1 \
--password ''

clear-test:
	@rm -rf testnet/node_01
	@rm -rf testnet/node_02
	@rm testnet/test1*


main-1:
	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/node_01 \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 127.0.0.1:41001 \

main-2:
	../../build/bin/lolnerod \
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
--add-exclusive-node 10.0.0.1

main-sync-debug:
	@rm -rf mainnet/node_sync

	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/node_sync \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 10.0.0.1 \
--log-level 1

main-sync-reuse:
	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/node_sync \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 10.0.0.1 \

main-sync-flake:
	@rm -rf mainnet/node_sync_flake

	../../result/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/node_sync_flake \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 10.0.0.1

mine:
	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/node_sync \
--p2p-bind-port 41000 \
--rpc-bind-port 45000 \
--add-exclusive-node 10.0.0.1 \
--start-mining hahaEwGNeu4AbYYrsrZmoVJUUpSWR3dQ3JuGyKJU8KKBXZVSND2duaiZUsWQcyrLEzSjH3Y4opmYJNHoBow6reYJ1iD6SQNjn4 \
--mining-threads 4

test-arg:
	../../build/bin/lolnerod help \
--rpc-bind-port 45000 \

tor-sync:
	@rm -rf mainnet/tor_sync

	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/tor_sync \
--p2p-bind-port 41002 \
--rpc-bind-port 45002 \
--proxy tor,127.0.0.1:9063,10 \
--add-exclusive-node lolpjcqr2woffv6h4mvw4ftq5yea4faiot4gfkzky63zuzvbwmglvuyd.onion \

clearnet-proxy-sync:
	rm -rf mainnet/clearnet_proxy_sync

	../../build/bin/lolnerod \
--hide-my-port \
--data-dir ./mainnet/clearnet_proxy_sync \
--p2p-bind-port 41002 \
--rpc-bind-port 45002 \
--proxy public,127.0.0.1:9063,10 \

tor-proxy-full:
	rm -rf mainnet/tor_proxy_full

	../../build/bin/lolnerod \
--data-dir ./mainnet/tor_proxy_full \
--rpc-bind-port 45002 \
--proxy public,127.0.0.1:9063 \
--proxy tor,127.0.0.1:9063 \

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
