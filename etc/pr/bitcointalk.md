Lolnero is a fork of Wownero with a linear emission and a SHA-3 PoW.

There is no premine and no dev tax.

Source code: https://gitlab.com/lolnero/lolnero

Lolnero was launched on Oct 10th, 2020.

The date was determined by this twitter poll:

https://twitter.com/101n3r0/status/1313197529027112960


Updates:

Oct 21th, 2021

Lolnero moved to GPU mining, since there's a built-in OpenCL miner now. What's interesting is the speed this miner got developed. It literally only took 4 days. Thanks to [cruzbit](https://github.com/cruzbit/cruzbit) which provided a solid opencl code base to work on.


Sep 11th, 2021

Tx extra has been reworked to only include tx output public keys. It's probably how sub-address was intended to be used. More refactoring has been done that made further work on wallet code possible. This is actually huge.


Sep 6th, 2021

We changed our payment proof, which is what one uses to settle a dispute out of band, from 64 bytes to 128 bytes. Monero/wownero uses a single schnorr signature for two public keys, we use two.

Our implementation is just dumb but there's no room for mistakes, two signatures, two keys, easy.


Sep 1st, 2021

Twitter blocked this account, and I'm [i]not[/i] interested in getting it back. We are too good for it.


Aug 14th, 2021

A lot happened behind the scene. We dropped most of the internally maintained curve25519 code and instead relies on libsodium for curve operations. We unified the data types from ringct and crypto, and at the same time split the key type into key (point) and scalar, the way the original cryptonote developers structured their types.

We took advantage of the overloading capability of C++ to make the point and scalar type aware of the + - * operators so we can use these in the code to better match how we think about algorithms. We start to replace raw for loops with std algorithms because they have the potential in the future to be parallelized. Currently android NDK is the blocker for adding parallelization. Hopefully google can put their shit together and not suck on making NDK anymore.


Jul 26th, 2021

No hardfork is kind of boring but that's the way it is. We reduced the code size down to about 72k lines of code, which gave us a build time less than 2 minutes with clang on a 6 cores ryzen.

On the haskell side, I tried to share some development screenshot on twitter, but some miner started to panic thinking I was able to add blocks with a terminal. So I'll try not to share development on twitter mindlessly. Anyway, we are able to talk the levin protocol now, but only tested with handshake. The next step, only brainstorming obviously, is to probably somehow build a state machine that can capture the entire p2p protocol, so we can discard the http server. Because we already have full parsing of all the blockchain data, we should be able to reconstruct the entire database acting only as a  regular node.

The next thing is probably to build something useful with it, like an explorer or a backup service, or something.


May 4th, 2021

Nothing really happened, but since wownero mooned, it's probably worthwhile to see where we can fit in this new landscape.

Out primary competitor wownero is a legitimate coin. It's pretty much impossible to beat a legitimate coin once it mooned, assuming you all agree? So where do we go from here. The maintenance cost of lolnero is pretty low, so the chain will likely stay with pretty much no maintenance needed. The parallel implementation in Haskell is still on the roadmap, but I need to find some time to do it as a hobby, cuz there's no funding, it has to be a hobby ;) I'm still pretty interested nevertheless.

So yes, lolnero will just be like before, happy CPU mining.


April 18th, 2021

So we had an integer overflow bug in our difficulty adjustment algorithm (DAA). There are good news and bad news, which do yo want to hear?

Since we didn't die, let's start with the bad news. Out of the first 278 blocks, the first half have hard coded constant difficulty so these are fine, the rest all have overflowed difficulty with no exception  :-X

OK, the good news. Because our relatively low hashrate, after the first 278 blocks, the difficulty never overflowed, and since we fixed the algorithm it shouldn't overflow ever again. We were a little bit luckier than wownero, since its difficulty was at the edge of overflowing, which made hot fixing a nightmare.

There you have it. Happy mining, until the next bug kills us all.


April 10th 2021

We have a website now, legit as fuck.

https://lolnero.org/


Marth 31th, 2021

We simplified the daemon CLI even more, I know. We removed another boost dependency, it's actually harder than it seems, but it was done.


Marth 29th, 2021

We enabled pretty much all the unit tests and they are auto run on rebuild, well, with our build script. The default cmake configuration does not build tests. We enabled C++20 just for fun, I mean we are allowed to have some fun right? We cleaned up the interface for wallet cli even more, so it's less of a mess at least from the outside.


Marth 25th, 2021

We finally brought back some unit tests, so from now on, every new release will be guarded by these revived tests. We are not sure if more, like the core tests and functional tests, can be added, since we need completely different test data. For now, unit tests are what we have. It's better than nothing right?


Marth 20th, 2021

After observing some cryptocurrency got spammed, we decided to make the block size limit a linear function of the block height to prevent spams. Lolnero tries to target mobile users, so we want running a node to be as cheap as possible, and a large blockchain which might be acceptable on the server but too costly on mobile is not something we want.

The linear function is the identity function, with a minimum value of 128k.


Marth 12th, 2021

Android node:
https://play.google.com/store/apps/details?id=org.lolnero.node

Android seed generator:
https://play.google.com/store/apps/details?id=org.lolnero.lolnero_seed

Android wallet:
https://play.google.com/store/apps/details?id=org.lolnero.lolnero_wallet

We never really explained the technical details of why SHA3 or any light weight POW is important for lolnero, now it seems to be a good time.

The current set up of a mobile wallet requires three processes to work simultaneously, specifically the flutter rendering process, the wallet-rpc server and the node. They all need to be relatively responsive for an acceptable user experience, in particularly the daemon can not be unresponsive for several seconds trying to validate pow for several blocks, which currently is the case for wownero and monero. To be fair, this set up, a full validating node on mobile, is not strictly required for a privacy coin to work, but this is what we are after, and what makes lolnero special. 


Marth 9th, 2021

We submitted the mobile seed generator and the mobile wallet to the play store, they are both waiting for review.

https://gitlab.com/fuwa/lolnero-seed
https://gitlab.com/fuwa/lolnero-wallet

From out testing, they work alright, so lolnero should be mobile ready, hopefully.


Marth 6th, 2021

We've been hacking on some C++. Latest cmake 3.20 beta and android ndk 23 beta allow us to build for android again, so "lolnero node" is back on the play store:

https://play.google.com/store/apps/details?id=org.lolnero.node

These tools also allow us to build the wallet, which has not been ported yet. We were worried that we might have to build a seed generator using the C++ code, but after looking a bit deeper on how the seed is converted into keys, we are confident that this is unnecessary, since a "scaler_reduce" is part of the key generation process, which means that any value, no matter how large, is a valid key thanks to modular arithmetic, math basically.

So a mobile seed generator is also on the road map.

We made the wallet cli even simpler to use, but again by removing some features which aren't essential for a wallet, like the view only feature. This can be added back with a new wallet, or a custom 3rd party wallet for a specific user group. We want to keep C++ to the bare minimal, right?


Feb 28th, 2021

So we are working on a rewrite. So far we have implemented

* tx (de)serialization
* block (de)serialization
* block pow validation
* an in ram database that can persist to disk

Pretty much half of monero-rs and a little bit more.

We won't post anything on twitter until there's a working daemon, but we'd like to share with you some findings. The entire thing is in 2k lines of haskell, and half of it is unit test. Varint parsing / building was like 6 lines of code. We use libraries like crazy. We don't plan to implement bulletproof validation, we want to wrap the C++ with a C API, and just call it from haskell. We don't care about batched verification, so we'll just iterate over it. We are experimenting with a new build system, since it requires some heavy duty tooling to manage this C++ beast.

There's still a lot to be done, so stay tuned :D 


Feb 19th, 2021

After some heavy refactoring of the original code base, mostly removing non-essential features. We are finally ready to start to work on the real goal of this project, a rewrite.

The goal is to have as many implementations as possible, but for now, we focus on a rewrite in haskell, for only one reason: that is the only language our current developer is willing to work with for free.

Anyway, haskell isn't completely useless and pretty much anything is better than C++.

We made the C++ implementation as maintainable as possible, so it should give us enough time to work on this. Good luck with your other investments.

P.S. Yes, we implemented tree-hash in haskell. I know, what a pathetic project.


Feb 13th, 2021

We made some further improvements to the code base by reducing the Lines of Code in the src/ folder from the original 159k down to 86k, which should gives us better future maintainability.

Some simplification to the consensus and protocol were also introduced, for example, a limited block size of 4MB and a removal of the some what unconventional block weight formula. In lolnero, block weight = block size, so these terms are interchangeable. We simplified the pseudo protocol involving the fields in tx_extra, by reduing the number of them from five or something down to two, so other wallet implementations can have less things to worry about to be compatible with the reference implementation.

We cleaned up the cmake build system to use only standard cmake functions, to make maintenance easier for the future. It also makes using other build system possible by having a somewhat cleaner reference build. This might be beneficial when porting to other platforms, which might not be well supported by cmake, like the current situation on android.

We refactored the wallet2.(h/cpp) module significantly,  but that's just another taste on how code should be organized :p

To wrap up, we really want to have maintainable code, so we have something we are relatively comfortable to store some value in.


Feb 5th, 2021

We were ready to pull the plug, but there was this miner that refused to leave  >:(

Anyway, guess this network will keep running for some unspecified extended period of time ...


Jan 10th, 2021

It seems this project failed to attract any attention, the seed node will be taken down once most miners left, thanks for not contributing anything really. It's a fun experiment anyway.


Dec 24th, 2020

How's everyone? We made some huge "improvements" to the code base by reducing its size. But unlike other projects,
you don't need to upgrade if you don't feel like it, since there's no hardforks  ;)

Have a nice holiday.


Dec 6th, 2020

Enabled socks4a for clear net. To use Tor for everything (clear net and hidden services), start the daemon like this:

[code]
lolnerod \
--proxy public,127.0.0.1:9050 \
--proxy tor,127.0.0.1:9050
[/code]

So you don't need to run it under torsocks :D


Dec 5th, 2020

Full Tor support has been added / restored with the latest code, use 

[code]--proxy tor,127.0.0.1:9050,10[/code]

to enable access to the built-in seed node.

You can block clear net at the firewall level and the blockchain should continue to work :D


Nov 4th, 2020

Mobile node is available:
https://play.google.com/store/apps/details?id=org.lolnero.node


Oct 11th, 2020 - 3

We are online at height 1, join us!


Oct 11th, 2020 - 2

We will launch again at Oct 11th, 2020, 16:00 (UTC), see you there!


Oct 11th, 2020

It seems the seed node isn't accepting connections, we'll try to fix it later, and possibly relaunch. Thanks :D


Oct 10th, 2020

We'll likely launch on Oct 10th, 2020, 21:00 (UTC) !

