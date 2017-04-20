var sodium = require('libsodium-wrappers-sumo');
var CRC32 = require('crc-32');
var net = require('net');
var chacha = require('chacha');

var MESSAGESIZE = 136;
var HEADERSIZE = 4;
var PUBKEYINDEX = 4;
var PUBKEYSIZE = 32;
var IVSIZE = 12;
var SIGNATURESIZE = 64;
var CRCSIZE = 4;


function debug(message) {

    if(debugEnabled) {
        console.log(message);
    }

}

process.on('SIGINT', function() { debug('caught ctrl+c...'); process.exit(); });
process.on('SIGTERM', function() { debug('caught kill...'); process.exit(); });


debug("libsodium version: "+sodium.sodium_version_string());

//debug(Object.keys(sodium));

var debugEnabled = false;

//Public
module.exports = function(host,port,pubserver,pubclient,privclient,debugflag) {

    if(host==null||port==null) {
        throw 'no host or port!';
    }
    if(pubserver==null||pubclient==null||privclient==null) {
        throw 'serverpubkey, clientpubkey, clientprivkey necessary';
    }
    var HOST = host;
    var PORT = port;
    var clientprivkey = privclient; 
    var clientpubkey = pubclient;
    var serverpubkey = pubserver;
    var cipher =  null;
    var decipher =  null;
    var sessionkeypair = sodium.crypto_box_keypair();
    var client = new net.Socket();
    var connected = true;
    var usercallback = null;

    if(debugflag!=null) {
        debugEnabled = debugflag;
    }

    this.isConnected = function isConnected() {
        return connected;
    }

    function listeners(ev,data) {
        if(usercallback!=null) {
            usercallback(ev,data);
        }
    }

    this.connect = function misc(callback) {
        if(callback!=null) {
            usercallback = callback;
        }
        var requestmessage = createSessionRequest(sessionkeypair,clientpubkey,clientprivkey);

        client.connect(PORT, HOST, function() {
	        debug('Connected');
            listeners('connected','');
	        client.write(new Buffer(requestmessage));
        });
        client.on('error', function(ex) {
            listeners('error',ex);
            debug("handled error");
            debug(ex);
            process.exit();
        });
        client.on('data', (buffer) => {
	        debug(buffer);
	        var response = createHexString(buffer);
	        debug('buffer len: '+buffer.length);
	        debug('Received: ' + response);
            if(isSessionResponse(buffer)) {
                if(handleStartSessionResponse(buffer)) {
                    listeners("sessionstart",'');
                } else {
                   listeners("sessionerror",'');
                }
            } else {
	            if(buffer.length!=MESSAGESIZE) {
		            throw 'response length != '+MESSAGESIZE+' bytes'; 
	            }
	            if(!hasHeader(buffer)) {
		            throw 'no header found!';	
	            }	
                debug("crypted message received: "+createHexString(buffer));
                var decryptedmessage = decryptmes(buffer);
                debug("decrypted message: "+createHexString(decryptedmessage));
                if(verifyChecksum(decryptedmessage)) {
                    listeners('data',decryptedmessage);
                }
            }
        });
    }

   this.send = function send(mestype,message) {
        if(message.length>(MESSAGESIZE-HEADERSIZE-CRCSIZE)) {
            throw 'message size > '+(MESSAGESIZE-HEADERSIZE-CRCSIZE);	
        }
        var request = new Uint8Array(MESSAGESIZE);
        setHeader(request,mestype);
        for(var i = 0; i < message.length; i++) {
            request[HEADERSIZE+i]=message[i];
        }
        setChecksum(request);
        client.write(new Buffer(crypt(request)));
    }

    function handleStartSessionResponse(arr) {

		debug("startsessionresponse");	
		var sessionpubkey = arr.subarray(PUBKEYINDEX,PUBKEYINDEX+PUBKEYSIZE);
		var iv = arr.subarray(PUBKEYINDEX+PUBKEYSIZE,PUBKEYINDEX+PUBKEYSIZE+IVSIZE);
		var message = arr.subarray(PUBKEYINDEX,PUBKEYINDEX+PUBKEYSIZE+IVSIZE);
		var signature = arr.subarray(PUBKEYINDEX+PUBKEYSIZE+IVSIZE,PUBKEYINDEX+PUBKEYSIZE+IVSIZE+SIGNATURESIZE);
		debug("session pub key: "+createHexString(sessionpubkey));
		debug("session iv: "+createHexString(iv));
		debug("session signature: "+createHexString(signature));
		if (sodium.crypto_sign_verify_detached(signature, message,Uint8Array.from(serverpubkey))) {
			debug("signature valid!")	;
            var secret = sodium.crypto_scalarmult(sessionkeypair.privateKey, Uint8Array.from(sessionpubkey));
            cipher =  chacha.ChaCha20(new Buffer(secret), new Buffer(iv));
            decipher =  chacha.ChaCha20(new Buffer(secret), new Buffer(iv));
            debug("secret: "+createHexString(secret));
            return true;
		} else {
			debug("signature invalid!")	
		}
        return false;
    }


    function crypt(mess) {
        var crypted = cipher.update(new Buffer(mess.subarray(HEADERSIZE,mess.length+HEADERSIZE)));
         var response = new Uint8Array(MESSAGESIZE);
        for(var i = 0; i < HEADERSIZE; i++) {
            response[i]=mess[i];
        }
        for(var i = 0; i < response.length+HEADERSIZE; i++) {
                response[HEADERSIZE+i] = crypted[i];
        }
        
        
        return response;
    }

    function decryptmes(mess) {
        var decrypted = decipher.update(new Buffer(mess.subarray(HEADERSIZE,mess.length+HEADERSIZE)));

        var response = new Uint8Array(MESSAGESIZE);
        for(var i = 0; i < HEADERSIZE; i++) {
            response[i]=mess[i];
        }
        for(var i = 0; i < response.length+HEADERSIZE; i++) {
                response[HEADERSIZE+i] = decrypted[i];
        }
        return response;
    }

} // doorkeeper class end


function createHexString(arr) {
    var result = "";

    for (var i = 0; i < arr.length; i++) {
        var lef = arr[i] & 0xf0;
        lef = lef>>4;
        var rig = arr[i] & 0x0f;

        result += lookupTable[lef]+lookupTable[rig];
    }

    return result;
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

var lookupTable = {
  0x00 : "0",
  0x01 : "1",
  0x02 : "2",
  0x03 : "3",
  0x04 : "4",
  0x05 : "5",
  0x06 : "6",
  0x07 : "7",
  0x08 : "8",
  0x09 : "9",
  0x0a : "a",
  0x0b : "b",
  0x0c : "c",
  0x0d : "d",
  0x0e : "e",
  0x0f : "f"

 
};

module.exports.parseHexString = function parseHexString(str) { 
    var result = [];
    while (str.length >= 2) { 
        result.push(parseInt(str.substring(0, 2), 16));

        str = str.substring(2, str.length);
    }
    return result;
}

function toBytesInt32 (num) {
    arr = [
         (num & 0xff000000) >> 24,
         (num & 0x00ff0000) >> 16,
         (num & 0x0000ff00) >> 8,
         (num & 0x000000ff)
    ];
    return arr;
}

function fromBytesInt32 (arr) {
    var integer = arr[0];
    integer <<= 8;
    integer |= arr[1];
    integer <<= 8;
    integer |= arr[2];
    integer <<= 8;
    integer |= arr[3];

    return integer;
}

function isLE() {
    var arrayBuffer = new ArrayBuffer(2);
    var uint8Array = new Uint8Array(arrayBuffer);
    var uint16array = new Uint16Array(arrayBuffer);
    uint8Array[0] = 0x23; // set first byte
    uint8Array[1] = 0x42; // set second byte    
    if(uint16array[0] === 0x2342) {
        debug("bendian");
        return false;
    }
    debug("lendian");
    return true;
}

function toBigEndian (num) {
    arr = [
         num[3],
         num[2],
         num[1],
         num[0]
    ];
    return arr;
}

function fromBigEndian (num) {
    arr = [
         num[0],
         num[1],
         num[2],
         num[3]
    ];
    return arr;
}

function setHeader(mes,type) {
    mes[0]=0x23;
    mes[1]=0x42;
    mes[2]=type;
    mes[3]=0x00;
}

    function calcChecksum(mes) {
        var signmessage = mes.subarray(HEADERSIZE,MESSAGESIZE-CRCSIZE);
        debug("sign message: "+createHexString(signmessage));

        var startSessionCRC = CRC32.buf(signmessage);

        return startSessionCRC;
    }

    function setChecksum(mes) {

        var mescrc = calcChecksum(mes);
        var crc = toBytesInt32(mescrc);
        var crcbytes = crc;
        if(isLE()) {
            crcbytes = toBigEndian(crc);
        } 

        for(var i = 0; i < CRCSIZE; i++) {
            mes[(MESSAGESIZE-CRCSIZE)+i]=crcbytes[i];
        }

    }

    function verifyChecksum(mes) {

        var calcrc = calcChecksum(mes);
        var mescrcbytes = new Buffer(mes.subarray(MESSAGESIZE-CRCSIZE,MESSAGESIZE));

        if(isLE()) {
            mescrc = mescrcbytes.readUInt32LE(0);
        } else {
            mescrc = mescrcbytes.readUInt32BE(0);
        }

        if(mescrc === calcrc) {
            return true;
        }
        return false;

    }

function createSessionRequest(sessionkeypair, clientpubkey, clientprivkey) {

    var requestmessage = new Uint8Array(MESSAGESIZE);
    setHeader(requestmessage,0x10);

    for(var i = 0; i < PUBKEYSIZE; i++) {
        requestmessage[HEADERSIZE+i]=sessionkeypair.publicKey[i];
    }
    var startSessionSignature = sodium.crypto_sign(new Buffer(sessionkeypair.publicKey), new Buffer(clientprivkey));
    for(var i = 0; i < SIGNATURESIZE; i++) {
        requestmessage[HEADERSIZE+PUBKEYSIZE+i]=startSessionSignature[i];
    }
    for(var i = 0; i < PUBKEYSIZE; i++) {
        requestmessage[HEADERSIZE+PUBKEYSIZE+SIGNATURESIZE+i]=clientpubkey[i];
    }
    setChecksum(requestmessage);

	debug("session pub key: "+createHexString(sessionkeypair.publicKey));
	debug("session signature: "+createHexString(startSessionSignature));
	debug("client pub key: "+createHexString(clientpubkey));
	debug("session crc: "+createHexString(requestmessage.subarray(MESSAGESIZE-CRCSIZE,MESSAGESIZE)));

    return requestmessage;

}


function hasHeader(mes) {

	if(mes[0]==0x23&&mes[1]==0x42) {
		return true;	
	}	
    return false;
}

function isSessionResponse(mes) {

	if(hasHeader(mes) && mes[2]==0x20) {
		return true;	
	}	
    return false;
}




