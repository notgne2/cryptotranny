// Always use strict mode
"use strict";

// Dependencies
const EventEmitter = require ('events').EventEmitter;
const net          = require ('net');
const lpstream     = require ('length-prefixed-stream');
const nacl         = require ('tweetnacl');

// Basic wrapper of `net` socket which deliminates chunks by a length prefix
class NetConn extends EventEmitter {
  constructor (socket) {
    // Induce parent class creation
    super ();

    // Set private variables
    this._socket = socket;
    this._socketDecoder = lpstream.decode ();
    this._socketEncoder = lpstream.encode ();

    // Pipe data through the right places
    this._socketEncoder.pipe (this._socket);
    this._socket.pipe (this._socketDecoder)

    // Listen for events
    this._listen ();
  }

  // Listen for events
  _listen () {
    // Listen for data from socket decoder
    this._socketDecoder.on ('data', (data) => {
      // Emit recieved data
      this.emit ('data', data);
    });

    this._socket.on ('close', () => {
      this.emit ('disconnected');
    });
  }

  // Send data over socket
  send (data) {
    // Write data to the encoding stream
    this._socketEncoder.write (data);
  }

  // Destroy underlying sock connection
  destroy () {
    this._socket.destroy ();
  }
}

// Create encrypted comm transport around a `NetConn`
class CryptoComm extends EventEmitter {
  constructor (netConn, theirPk, ourSk) {
    // Induce parent class
    super ();

    // Public properties
    this.pk = theirPk;

    // Private properties
    this._netConn = netConn;

    this._theirPk = theirPk;
    this._ourSk   = ourSk;

    // Listen for events
    this._listen ();
  }

  // Listen for events
  _listen () {
    this._netConn.on ('data', (data) => {
      this._onData (data);
    });

    this._netConn.on ('disconnected', () => {
      this.emit ('disconnected');
    });
  }

  // Handle recieved from conn
  _onData (data) {
    // Decude the data to a JSON object
    let decodedData = JSON.parse(data.toString ());

    // Get `encryptedData` and `nonce` as buffers
    let encryptedData = Buffer.from (decodedData.data, 'base64');
    let nonce = Buffer.from (decodedData.nonce, 'base64');

    // Decrypt contained data
    let decryptedData = nacl.box.open (encryptedData, nonce, this._theirPk, this._ourSk);

    if (decryptedData == null) {
      return // Unable to decrypt, probably somebody trying to intercept
    }

    // Emit data over self
    this.emit ('message', Buffer.from(decryptedData));
  }

  // Send message over comm
  send (data) {
    // Generate a random nonce
    let nonce = nacl.randomBytes (nacl.box.nonceLength);

    // Encrypt data
    let encryptedData = nacl.box (data, nonce, this._theirPk, this._ourSk);

    // JSON encode an object containing stringified `data` and `nonce`
    let encodedData = Buffer.from (JSON.stringify ({
      data  : Buffer.from (encryptedData).toString ('base64'),
      nonce : Buffer.from (nonce).toString ('base64'),
    }));

    // Send encoded data over conn
    this._netConn.send (encodedData);
  }

  // Destroy underlying netconn
  destroy () {
    this._netConn.destroy ();
  }
}

// TrannyServer class which emits new `CryptoComm` clients
class TrannyServer extends EventEmitter {
  constructor (keyPair, port) {
    // Induce parent class
    super ();

    // Create tcp server
    let tcpServer = net.createServer ((socket) => {
      // Create new conn for recieved socket
      let netConn = new NetConn (socket);

      // Listen for first data on conn
      netConn.once ('data', (data) => {
        // First data is always public key, use to create a `CryptoComm`
        let comm = new CryptoComm (netConn, data, keyPair.sk);
        // Emit new comm on self
        this.emit ('client', comm);
      });
    });

    // Listen on supplied port
    tcpServer.listen (port);
  }
}

// TrannyClient which implements `CryptoComm` taking a few connection options
class TrannyClient extends CryptoComm {
  constructor (host, port, keyPair, theirPk) {
    // Create new net socket connection to target host
    let socket = net.createConnection ({ host: host, port: port });

    // Create new conn for socket
    let netConn = new NetConn (socket);

    // Send our public key over socket
    netConn.send (keyPair.pk);

    // Induce parent with the conn and key data
    super (netConn, theirPk, keyPair.sk);
  }
}

// Generate a keypair
function genKeyPair () {
  // Generate keys using nacl
  let naclKeyPair = nacl.box.keyPair ();

  // Return in cryptotranny formatting
  return {
    pk : Buffer.from (naclKeyPair.publicKey),
    sk : Buffer.from (naclKeyPair.secretKey),
  };
}

// Exports
exports = module.exports = { TrannyServer, TrannyClient, genKeyPair };