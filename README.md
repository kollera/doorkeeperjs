# doorkeeperjs

A hacked node.js client for [doorkeeper](https://github.com/kollera/DoorKeeper).


## Usage

````

var doorkeeper = require('doorkeeper');
const fs = require('fs');

var PORT = 23;
var HOST = '192.168.1.1';

// server public key / ed25519 / 32 bytes
var serverpubkey = doorkeeper.parseHexString('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
// client public key / ed25519 / 32 bytes
var clientpubkey = doorkeeper.parseHexString('a56a9adb8b009e47acc913c51adbc33e2444bcb0590479b40e02d244c7cec1ac');
// client private key / ed25519 / 64 bytes
var clientprivkey = doorkeeper.parseHexString('59d183c8e84b50d73cf873080ecf0fb1b0e34d30f0e866a0635de79fd831e11ca56a9adb8b009e47acc913c51adbc33e2444bcb0590479b40e02d244c7cec1ac');

var client = new doorkeeper(HOST,PORT,serverpubkey,clientpubkey,clientprivkey,true);
client.connect(function(ev,data) {
    console.log("cb ev: "+ev);
    console.log("cb data: "+data);
    if(ev=='sessionstart') {
    	// session started
        client.send(0x01,[]);
    }
});

````

