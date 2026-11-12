const { test } = require('uvu')
const assert = require('uvu/assert')
const nodeCrypto = require('crypto')
const { encrypt, decrypt, isEncrypted, versionOf, generateKey, latestVersion, normalizeKeys } = require('../src/crypto')

const KEY = generateKey()

// The two functions from the blog post, verbatim, to prove the formats are interchangeable.
function blogEncrypt(plaintext, ENV_KEY) {
  const key = Buffer.from(ENV_KEY, 'base64')
  const iv = nodeCrypto.randomBytes(12)
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv)
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `enc:v1:${Buffer.concat([iv, tag, data]).toString('base64')}`
}
function blogDecrypt(value, ENV_KEY) {
  if (!value || !value.startsWith('enc:v1:')) return value
  const raw = Buffer.from(value.slice('enc:v1:'.length), 'base64')
  const iv = raw.subarray(0, 12)
  const tag = raw.subarray(12, 28)
  const data = raw.subarray(28)
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', Buffer.from(ENV_KEY, 'base64'), iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8')
}

test('generateKey returns 32 random bytes as base64', () => {
  assert.is(Buffer.from(KEY, 'base64').length, 32)
  assert.is.not(generateKey(), generateKey())
})

test('encrypt and decrypt round trip', () => {
  const sealed = encrypt('sk_live_abc123', KEY)
  assert.ok(sealed.startsWith('enc:v1:'))
  assert.is(decrypt(sealed, KEY), 'sk_live_abc123')
})

test('round trips unicode, newlines and long values', () => {
  for (const value of ['pässwörd ✓ 日本語', 'line1\nline2\n', 'x'.repeat(5000), ' padded ', '-----BEGIN KEY-----\nabc\n-----END KEY-----']) {
    assert.is(decrypt(encrypt(value, KEY), KEY), value)
  }
})

test('the same plaintext encrypts to different ciphertext each time', () => {
  assert.is.not(encrypt('same', KEY), encrypt('same', KEY))
})

test('values from the blog post code decrypt here, and ours decrypt there', () => {
  assert.is(decrypt(blogEncrypt('from the blog', KEY), KEY), 'from the blog')
  assert.is(blogDecrypt(encrypt('from the package', KEY), KEY), 'from the package')
})

test('plaintext passes through decrypt untouched', () => {
  assert.is(decrypt('plain', KEY), 'plain')
  assert.is(decrypt('', KEY), '')
  assert.is(decrypt(undefined, KEY), undefined)
  assert.is(decrypt('encoded:v1:nope', KEY), 'encoded:v1:nope')
})

test('isEncrypted and versionOf', () => {
  assert.ok(isEncrypted('enc:v1:abc'))
  assert.ok(isEncrypted('enc:v12:abc'))
  assert.not.ok(isEncrypted('enc:v0:abc'))
  assert.not.ok(isEncrypted('enc:abc'))
  assert.not.ok(isEncrypted(undefined))
  assert.is(versionOf('enc:v3:abc'), 'v3')
  assert.is(versionOf('plain'), null)
})

test('a tampered value throws instead of returning garbage', () => {
  const sealed = encrypt('secret', KEY)
  const raw = Buffer.from(sealed.slice(7), 'base64')
  raw[raw.length - 1] ^= 1
  assert.throws(() => decrypt(`enc:v1:${raw.toString('base64')}`, KEY), /could not decrypt/)
})

test('the wrong key throws', () => {
  assert.throws(() => decrypt(encrypt('secret', KEY), generateKey()), /could not decrypt \(wrong v1 key/)
})

test('a truncated value throws', () => {
  assert.throws(() => decrypt('enc:v1:AAAA', KEY), /truncated/)
  assert.throws(() => decrypt('enc:v1:', KEY), /truncated/)
})

test('errors never contain the plaintext or the key', () => {
  const sealed = encrypt('super-secret-value', KEY)
  try {
    decrypt(sealed, generateKey())
    assert.unreachable()
  } catch (err) {
    assert.not.match(err.message, 'super-secret-value')
    assert.not.match(err.message, KEY)
  }
})

test('key versions: encrypt uses the highest, decrypt picks by prefix', () => {
  const keys = { v1: generateKey(), v2: generateKey(), v10: generateKey() }
  assert.is(latestVersion(keys), 'v10')
  const sealed = encrypt('x', keys)
  assert.ok(sealed.startsWith('enc:v10:'))
  assert.is(decrypt(sealed, keys), 'x')
  const old = encrypt('y', keys, { version: 'v1' })
  assert.ok(old.startsWith('enc:v1:'))
  assert.is(decrypt(old, keys), 'y')
})

test('decrypting a version with no key names the known versions', () => {
  const sealed = encrypt('x', { v2: KEY }, { version: 'v2' })
  assert.throws(() => decrypt(sealed, { v1: KEY }), /no key for enc:v2 values. Known key versions: v1/)
})

test('bad keys are rejected with a useful message', () => {
  assert.throws(() => encrypt('x', 'short'), /must be 32 bytes/)
  assert.throws(() => encrypt('x', ''), /key v1 is empty/)
  assert.throws(() => encrypt('x', {}), /no key given/)
  assert.throws(() => normalizeKeys({ prod: KEY }), /invalid key version "prod"/)
  assert.throws(() => encrypt('x', { v1: KEY }, { version: 'v2' }), /no key v2/)
  assert.throws(() => encrypt(123, KEY), /needs a string/)
})

test.run()
