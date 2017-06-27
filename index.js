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
  }

  // Send data over socket
  send (data) {
    // Write data to the encoding stream
    this._socketEncoder.write (data);
  }
}

// Create encrypted comm transport around a `NetConn`
class CryptoComm extends EventEmitter {
  constructor (netConn, theirPk, ourSk) {
    // Induce parent class
    super ();

    // Private variables
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

    // Emit data over self
    this.emit ('message', decryptedData);
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
}

// TrannyServer class which emits new `CryptoComm` clients
class TrannyServer extends EventEmitter {
  constructor (ourSk, port) {
    // Induce parent class
    super ();

    // Create tcp server
    let tcpServer = net.createServer ((socket) => {
      // Create new conn for recieved socket
      let netConn = new NetConn (socket);

      // Listen for first data on conn
      netConn.once ('data', (data) => {
        // First data is always public key, use to create a `CryptoComm`
        let comm = new CryptoComm (netConn, data, ourSk);
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
  constructor (host, port, ourPk, ourSk, theirPk) {
    // Create new net socket connection to target host
    let socket = net.createConnection ({ host: host, port: port });

    // Create new conn for socket
    let netConn = new NetConn (socket);

    // Send our public key over socket
    netConn.send (ourPk);

    // Induce parent with the conn and key data
    super (netConn, theirPk, ourSk);
  }
}

// Exports
exports = module.exports = { TrannyServer, TrannyClient };