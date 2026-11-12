const { encrypt, isEncrypted, versionOf, normalizeKeys, latestVersion } = require('./crypto')
const { resolveTarget } = require('./adapters')
const { writeMany } = require('./batch')

/**
 * @typedef {object} WriteEvent
 * @property {string} name
 * @property {string} target - adapter name
 * @property {string} label - where the value went
 * @property {string} version - key version of the ciphertext
 */

/**
 * @typedef {object} SealResult
 * @property {string} version - key version used for new ciphertext
 * @property {Record<string, string>} sealed - name → `enc:vN:` value
 * @property {WriteEvent[]} written
 */

/**
 * Encrypt values and write the ciphertext to one or more targets.
 * Values that are already encrypted are written as they are.
 *
 * @param {object} opts
 * @param {Record<string, string>} opts.values - name → plaintext
 * @param {import('./crypto').Keys} opts.keys
 * @param {(string | import('./adapters').Adapter)[]} [opts.targets] - target specs or adapters, default none (just encrypt)
 * @param {import('./adapters').TargetOptions} [opts.targetOptions]
 * @param {string} [opts.version] - key version, default: the highest
 * @param {boolean} [opts.dryRun] - encrypt but do not write
 * @param {(event: WriteEvent) => void} [opts.onWrite]
 * @param {import('./exec').Exec} [opts.exec]
 * @returns {Promise<SealResult>}
 *
 * @example
 * await seal({
 *   values: { STRIPE_SECRET_KEY: 'sk_live_...' },
 *   keys: ENV_KEYS,
 *   targets: ['netlify', 'ssm:/my-app/prod']
 * })
 */
async function seal(opts) {
  const keys = normalizeKeys(opts.keys)
  const version = opts.version || latestVersion(keys)
  const adapters = (opts.targets || []).map((target) => resolveTarget(target, opts.targetOptions, { exec: opts.exec }))

  /** @type {Record<string, string>} */
  const sealed = {}
  for (const name of Object.keys(opts.values)) {
    const value = opts.values[name]
    if (typeof value !== 'string' || value === '') {
      throw new Error(`preseal: ${name} has no value to encrypt`)
    }
    sealed[name] = isEncrypted(value) ? value : encrypt(value, keys, { version })
  }

  const written = []
  /** @type {[string, string][]} */
  const entries = Object.keys(sealed).map((name) => [name, sealed[name]])
  for (const adapter of adapters) {
    const report = (index) => {
      const [name, value] = entries[index]
      const event = { name, target: adapter.name, label: adapter.label || adapter.name, version: versionOf(value) }
      written.push(event)
      if (opts.onWrite) opts.onWrite(event)
    }
    if (opts.dryRun) entries.forEach((entry, index) => report(index))
    else await writeMany(adapter, entries, report)
  }

  return { version, sealed, written }
}

module.exports = { seal }
