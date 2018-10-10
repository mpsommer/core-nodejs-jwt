const fs = require('fs-extra');
const crypt = require('crypto');
const util = require('util');

// Regarding generating key pairs in Nodejs, it looks like it is close to being 
// part of the crypto module (https://github.com/nodejs/node/pull/22660).

// Creating keys:
// ssh-keygen -t rsa -b 2048 -f node_key.pem
// chmod 600 node_key.pem
// ssh-keygen -f node_key.pem.pub -m 'PEM' -e > node_key.pub.pem
// chmod 600 node_key.pub.pem

const privateKeyPath = '/path';
const publicKeyPath = '/path';
const privateKey = fs.readFileSync(privateKeyPath).toString();
const publicKey = fs.readFileSync(publicKeyPath).toString();

// Expiration date for the jwt.
const yearFromNow = new Date().setFullYear(new Date().getFullYear() + 1);

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

/**
 * @param {string} jwt 
 * @param {string | Object} publicKey 
 */
function verify(jwt: string, publicKey: string) {
  let signature = getJWTSignature(jwt);
  // First and second part of JWT string
  let headerAndPayload = getHeaderAndPayload(jwt);
  // signature = toBase64(signature);
  let verifier = crypt.createVerify('RSA-SHA256');
  verifier.update(headerAndPayload);
  return verifier.verify(publicKey, signature, 'base64');
}

/**
 * @param {object} payload,
 * @param {object} header,
 * @param {string} privateKey
 */
function sign(payload: object, header: object, privateKey: string) {
  let encodedHeaderPayload = encodeAndFormat(header, payload, 'utf8');
  const signer = crypt.createSign('RSA-SHA256');
  // Update the Sign content with the given data
  signer.update(encodedHeaderPayload)
  // Calculates the signature on all the data passed through using either 
  // sign.update() or sign.write(). Generates and returns a signature.
  let signature = signer.sign(privateKey, 'base64');
  return util.format('%s.%s', encodedHeaderPayload, signature);
}

/**
 * 
 * @param {object} header 
 * @param {object} payload 
 * @param {string} encoding 
 */
function encodeAndFormat(header: object, payload: object, encoding: string) {
  encoding = encoding || 'utf8';
  let encodedHeader = base64url(toBuffer(header, 'utf8'));
  let encodedPayload = base64url(toBuffer(payload, 'utf8'));
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

/**
 * 
 * @param {object} val 
 * @param {string} encoding 
 */
function toBuffer(val: object, encoding: string) {
  if (Buffer.isBuffer(val)) {
    return val;
  }
  if (typeof val === 'string') {
    return Buffer.from(val, encoding);
  }
  return Buffer.from(JSON.stringify(val), encoding);
}

/**
 * 
 * @param {Buffer} buf 
 */
function base64url(buf: Buffer) {
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * 
 * @param {string} jwt 
 */
function getJWTSignature(jwt: string) {
  return jwt.split('.')[2];
}

/**
 * 
 * @param {string} jwt 
 */
function getHeaderAndPayload(jwt: string) {
  return jwt.split('.', 2).join('.');
}


let jwtUtil = JWT();
let jwt = jwtUtil.sign(payload, header, privateKey);
let ver = jwtUtil.verify(jwt, publicKey);
console.log(ver);