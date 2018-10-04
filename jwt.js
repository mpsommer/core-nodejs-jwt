'use strict';
const fs = require('fs-extra');
const crypto = require('crypto');
const util = require('util');

// Regarding generating key pairs in Nodejs, it looks like it is close to being 
// part of the crypto module (https://github.com/nodejs/node/pull/22660).

// Creating keys:
// ssh-keygen -t rsa -b 2048 -f node_key.pem
// chmod 600 node_key.pem
// ssh-keygen -f node_key.pem.pub -m 'PEM' -e > node_key.pub.pem
// chmod 600 node_key.pub.pem

let privateKeyPath = 'path';
let publicKeyPath = 'path';
const privateKey = fs.readFileSync(privateKeyPath).toString();
let publicKey = fs.readFileSync(publicKeyPath).toString();

// Expiration date for the jwt.
let yearFromNow = new Date().setFullYear(new Date().getFullYear() + 1)

// Optional: 'secret': 'password',
let payload = {
  'issuer': 'mycompany.com',
  'kid': 'mycompany.com-001',
  'audience': 'someproduct',
  'exp': yearFromNow,
  'subject': 'some.user'
}

let header = {
  'alg': 'RS256',
  'typ': 'jwt',
  'kid': 'somecompany'
}

function JWT() {
  return {
    sign: sign,
    verify: verify,
  }
}

// TODO: GET type checking working somehow.


/**
 * @param {string} jwt 
 * @param {string | Object} publicKey 
 */
function verify(jwt, publicKey) {
  let signature = getJWTSignature(jwt);
  // First and second part of JWT string
  let headerAndPayload = getHeaderAndPayload(jwt);
  // signature = toBase64(signature);
  let verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(headerAndPayload);
  return verifier.verify(publicKey, signature, 'base64');
}

/**
 * @param {Object} payload
 * @param {string} privateKey
 */
function sign(payload, privateKey) {
  payload = serializeInput(payload);
  let encodedHeaderPayload = encodeAndFormat(header, payload, 'utf8');
  const signer = crypto.createSign('RSA-SHA256');
  // TODO: left off header, get documentation for signer...
  signer.update(encodedHeaderPayload)
  let signature = signer.sign(privateKey, 'base64');
  return util.format('%s.%s', encodedHeaderPayload, signature);
}

function encodeAndFormat(header, payload, encoding) {
  encoding = encoding || 'utf8';
  let encodedHeader = base64url(toBuffer(header));
  let encodedPayload = base64url(toBuffer(payload));
  return util.format('%s.%s', encodedHeader, encodedPayload);
}


function toBuffer(val, encoding) {
  if (Buffer.isBuffer(val)) {
    return val;
  }
  if (typeof val === 'string') {
    return Buffer.from(val, encoding || 'utf8');
  }
  if (typeof val === 'number') {
    // This won't work for very large or very small numbers, but is consistent
    // with previous behaviour at least
    val = val.toString();
    return Buffer.from(val, 'utf8');
  }
  return Buffer.from(JSON.stringify(val), 'utf8');
};

function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}


function serializeInput(thing) {
  if (!bufferOrString(thing)) {
    thing = JSON.stringify(thing);
  }
  return thing;
}

function bufferOrString(obj) {
  return Buffer.isBuffer(obj) || typeof obj === 'string';
}

function getJWTSignature(jwsSig) {
  return jwsSig.split('.')[2];
}

function getHeaderAndPayload(jwsSig) {
  return jwsSig.split('.', 2).join('.');
}


let jwtTool = JWT();
let jwt = jwtTool.sign(payload, privateKey);
// console.log(`jwt: ${jwt}`);

let ver = jwtTool.verify(jwt, publicKey);

console.log(ver);