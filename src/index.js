/*
Runtime entry point. Kept tiny on purpose: this is what your server code
loads, so it only pulls in node:crypto. The CLI, adapters and key-file
tooling live in other files and are never loaded from here.
*/
const {
  generateKey,
  normalizeKeys,
  latestVersion,
  isEncrypted,
  versionOf,
  encrypt,
  decrypt
} = require('./crypto')

/**
 * @typedef {import('./crypto').Keys} Keys
 */

/**
 * @typedef {object} EnvReader
 * @property {(name: string) => string} required - Read a variable, throw if it is unset or empty.
 * @property {(names?: string[]) => Record<string, string>} all - Decrypted values for `names` (default: every encrypted variable).
 * @property {(target?: Record<string, string | undefined>) => string[]} inject - Replace encrypted values in place with plaintext. Returns the names it decrypted.
 */

/**
 * Create an `env(name)` reader that decrypts `enc:vN:` values on read.
 * Plaintext values pass through untouched.
 *
 * @param {Keys} keys - base64 key, or `{ v1: '...', v2: '...' }`
 * @param {{ source?: Record<string, string | undefined> }} [opts] - where to read from, default `process.env`
 * @returns {((name: string, fallback?: string) => string | undefined) & EnvReader}
 *
 * @example
 * const env = createEnv({ v1: 'base64key' })
 * const stripe = require('stripe')(env('STRIPE_SECRET_KEY'))
 */
function createEnv(keys, opts = {}) {
  const map = normalizeKeys(keys)
  const source = opts.source || process.env
  const cache = new Map()

  function read(name) {
    const raw = source[name]
    if (!isEncrypted(raw)) return raw
    const hit = cache.get(name)
    if (hit && hit.raw === raw) return hit.value
    let value
    try {
      value = decrypt(raw, map)
    } catch (err) {
      // Name the variable, never the value.
      throw new Error(`${err.message.replace(/^preseal: /, `preseal: ${name}: `)}`)
    }
    cache.set(name, { raw, value })
    return value
  }

  function env(name, fallback) {
    const value = read(name)
    return (value === undefined || value === '') && fallback !== undefined ? fallback : value
  }

  env.required = function required(name) {
    const value = read(name)
    if (value === undefined || value === '') {
      throw new Error(`preseal: ${name} is not set`)
    }
    return value
  }

  env.all = function all(names) {
    const list = names || Object.keys(source).filter((name) => isEncrypted(source[name]))
    /** @type {Record<string, string>} */
    const out = {}
    for (const name of list) out[name] = read(name)
    return out
  }

  env.inject = function inject(target = source) {
    const names = Object.keys(target).filter((name) => isEncrypted(target[name]))
    // Decrypt everything first so a bad value leaves the target untouched.
    const values = names.map((name) => (target === source ? read(name) : decrypt(target[name], map)))
    names.forEach((name, i) => { target[name] = values[i] })
    return names
  }

  return env
}

module.exports = {
  createEnv,
  encrypt,
  decrypt,
  isEncrypted,
  versionOf,
  generateKey,
  latestVersion
}
