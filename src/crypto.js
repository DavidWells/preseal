const crypto = require('crypto')

/*
Wire format (same as the blog post, so values are interchangeable with the
40-line hand-rolled version):

  enc:<version>:base64( iv[12] || authTag[16] || ciphertext )

AES-256-GCM, 32-byte key, base64. The version names which key encrypted the
value, so several keys can be live at once during a rotation.
*/

const ALGORITHM = 'aes-256-gcm'
const IV_BYTES = 12
const TAG_BYTES = 16
const KEY_BYTES = 32
const ENCRYPTED_RE = /^enc:(v[1-9]\d*):/
const KEYGEN_HINT = 'Generate one with: npx preseal keygen'

/**
 * @typedef {string | Record<string, string>} Keys
 * A single base64 key (treated as `v1`), or a map of version to base64 key: `{ v1: '...', v2: '...' }`.
 */

/**
 * Generate a new random 256-bit key.
 * @returns {string} base64-encoded 32-byte key
 */
function generateKey() {
  return crypto.randomBytes(KEY_BYTES).toString('base64')
}

/**
 * @param {string} key - base64 key
 * @param {string} version
 * @returns {Buffer}
 */
function decodeKey(key, version) {
  if (typeof key !== 'string' || !key) {
    throw new Error(`preseal: key ${version} is empty. ${KEYGEN_HINT}`)
  }
  const buf = Buffer.from(key, 'base64')
  if (buf.length !== KEY_BYTES) {
    throw new Error(
      `preseal: key ${version} must be ${KEY_BYTES} bytes, base64-encoded (got ${buf.length} bytes). ${KEYGEN_HINT}`
    )
  }
  return buf
}

/**
 * Validate keys and return them as a version → base64 map.
 * @param {Keys} keys
 * @returns {Record<string, string>}
 */
function normalizeKeys(keys) {
  if (typeof keys === 'string') keys = { v1: keys }
  if (!keys || typeof keys !== 'object' || !Object.keys(keys).length) {
    throw new Error('preseal: no key given. Pass a base64 key or a map like { v1: "..." }')
  }
  /** @type {Record<string, string>} */
  const out = {}
  for (const version of Object.keys(keys)) {
    if (!/^v[1-9]\d*$/.test(version)) {
      throw new Error(`preseal: invalid key version "${version}". Versions look like v1, v2, v3`)
    }
    decodeKey(keys[version], version)
    out[version] = keys[version]
  }
  return out
}

/**
 * Highest key version in a key map.
 * @param {Record<string, string>} keys
 * @returns {string}
 */
function latestVersion(keys) {
  return Object.keys(keys).sort((a, b) => Number(b.slice(1)) - Number(a.slice(1)))[0]
}

/**
 * True when a value carries the `enc:vN:` prefix.
 * @param {unknown} value
 * @returns {boolean}
 */
function isEncrypted(value) {
  return typeof value === 'string' && ENCRYPTED_RE.test(value)
}

/**
 * Key version of an encrypted value, or null for plaintext.
 * @param {unknown} value
 * @returns {string | null}
 */
function versionOf(value) {
  const match = typeof value === 'string' && ENCRYPTED_RE.exec(value)
  return match ? match[1] : null
}

/**
 * Encrypt a plaintext string.
 * @param {string} plaintext
 * @param {Keys} keys
 * @param {{ version?: string }} [opts] - key version to use, default: the highest one
 * @returns {string} `enc:<version>:<base64>`
 */
function encrypt(plaintext, keys, opts = {}) {
  if (typeof plaintext !== 'string') {
    throw new Error('preseal: encrypt() needs a string')
  }
  const map = normalizeKeys(keys)
  const version = opts.version || latestVersion(map)
  if (!map[version]) {
    throw new Error(`preseal: no key ${version}. Known key versions: ${Object.keys(map).join(', ')}`)
  }
  const iv = crypto.randomBytes(IV_BYTES)
  const cipher = crypto.createCipheriv(ALGORITHM, decodeKey(map[version], version), iv)
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `enc:${version}:${Buffer.concat([iv, tag, data]).toString('base64')}`
}

/**
 * Decrypt an `enc:vN:` value. Anything without the prefix is returned as is,
 * so local `.env` files and non-secret config keep working.
 * @param {string | undefined} value
 * @param {Keys} keys
 * @returns {string | undefined}
 */
function decrypt(value, keys) {
  const match = typeof value === 'string' && ENCRYPTED_RE.exec(value)
  if (!match) return value
  const version = match[1]
  const map = typeof keys === 'string' ? { v1: keys } : (keys || {})
  if (!map[version]) {
    const known = Object.keys(map).join(', ') || 'none'
    throw new Error(`preseal: no key for enc:${version} values. Known key versions: ${known}`)
  }
  const raw = Buffer.from(value.slice(match[0].length).trim(), 'base64')
  if (raw.length < IV_BYTES + TAG_BYTES) {
    throw new Error('preseal: encrypted value is truncated or not base64')
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, decodeKey(map[version], version), raw.subarray(0, IV_BYTES), {
    authTagLength: TAG_BYTES
  })
  decipher.setAuthTag(raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES))
  try {
    return Buffer.concat([decipher.update(raw.subarray(IV_BYTES + TAG_BYTES)), decipher.final()]).toString('utf8')
  } catch (err) {
    throw new Error(`preseal: could not decrypt (wrong ${version} key, or the value was changed)`)
  }
}

module.exports = {
  generateKey,
  normalizeKeys,
  latestVersion,
  isEncrypted,
  versionOf,
  encrypt,
  decrypt
}
