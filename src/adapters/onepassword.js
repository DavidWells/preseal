const { exec: defaultExec } = require('../exec')
const { readOne } = require('../batch')

// In `op` assignment statements, periods, equals signs and backslashes in a
// section or field name are escaped with a backslash. Values are literal.
function escapeName(name) {
  return name.replace(/[\\.=]/g, '\\$&')
}

/**
 * Read a 1Password secret reference. Prefers `op-stash` (one Touch ID prompt,
 * then cached) and falls back to `op read`.
 * @param {string} ref - `op://vault/item/field`
 * @param {import('../exec').Exec} [exec]
 * @returns {Promise<string>}
 */
async function readOpRef(ref, exec = defaultExec) {
  let result
  try {
    result = await exec('op-stash', ['read', ref])
  } catch (err) {
    if (/** @type {any} */ (err).code !== 'ENOENT') throw err
    result = await exec('op', ['read', ref])
  }
  return result.stdout.replace(/\r?\n$/, '')
}

/**
 * A 1Password item, through the `op` CLI. Each variable becomes a field on
 * the item, named after the variable. The item is created (as a Secure Note)
 * when it does not exist yet.
 *
 * @param {object} opts
 * @param {string} opts.vault
 * @param {string} opts.item
 * @param {string} [opts.section]
 * @param {string} [opts.fieldType] - concealed (default) or text
 * @param {{ exec?: import('../exec').Exec }} [deps]
 * @returns {import('./index').Adapter}
 */
function createOnePasswordAdapter(opts, deps = {}) {
  const exec = deps.exec || defaultExec
  if (!opts || !opts.vault || !opts.item) {
    throw new Error('preseal: the 1Password target needs a vault and an item, like op://Engineering/my-app')
  }
  const fieldType = opts.fieldType || 'concealed'
  const ref = `op://${opts.vault}/${opts.item}${opts.section ? `/${opts.section}` : ''}`

  function assignment(name, value) {
    const field = opts.section ? `${escapeName(opts.section)}.${escapeName(name)}` : escapeName(name)
    return `${field}[${fieldType}]=${value}`
  }

  // Edit first and create on "not an item": one Touch ID prompt in the common case.
  async function write(assignments) {
    const edit = await exec('op', ['item', 'edit', opts.item, '--vault', opts.vault, ...assignments], { allowFail: true })
    if (edit.code === 0) return
    // op 2.34: `"my-app" isn't an item in the "Engineering" vault.`
    if (!/isn't an item/i.test(edit.stderr)) {
      throw new Error(`preseal: \`op item edit\` failed (exit ${edit.code}):\n${edit.stderr.trim()}`)
    }
    await exec('op', [
      'item', 'create', '--category', 'Secure Note', '--title', opts.item, '--vault', opts.vault,
      ...assignments
    ])
  }

  return {
    name: '1password',
    label: `1Password (${ref}/<NAME>)`,
    async set(name, value) {
      await write([assignment(name, value)])
    },
    // One `op item edit` (one Touch ID prompt) for many fields.
    async setMany(entries) {
      let batch = []
      let bytes = 0
      for (const [name, value] of entries) {
        const next = assignment(name, value)
        if (batch.length && (batch.length >= MAX_ASSIGNMENTS || bytes + next.length > MAX_ARG_BYTES)) {
          await write(batch)
          batch = []
          bytes = 0
        }
        batch.push(next)
        bytes += next.length
      }
      if (batch.length) await write(batch)
    },
    async get(name) {
      // Plain `op read`, never op-stash: its cache would hand `check` and
      // `reseal` the value from before our own write for up to five minutes.
      try {
        const { stdout } = await exec('op', ['read', `${ref}/${name}`])
        return stdout.replace(/\r?\n$/, '')
      } catch (err) {
        // A field or item that doesn't exist is "not set", not a failure.
        if (/does not have a field|isn't an item/i.test(err.message)) return undefined
        throw err
      }
    },
    // One `op item get` (one Touch ID prompt) instead of one `op read` per
    // name. Only a field that matches unambiguously is taken from it; anything
    // else goes through `get`, so `op read` stays the judge of odd cases.
    async getMany(names) {
      let fields = null
      try {
        const { stdout } = await exec('op', ['item', 'get', opts.item, '--vault', opts.vault, '--format', 'json'])
        const parsed = JSON.parse(stdout)
        if (parsed && Array.isArray(parsed.fields)) fields = parsed.fields
      } catch (err) {
        // No such item: every `op read` would say the same, so nothing is set.
        if (/isn't an item/i.test(err.message)) return names.map(() => ({ value: undefined }))
      }
      const results = []
      for (const name of names) {
        const matches = fields ? fields.filter((field) => field && field.label === name) : []
        const field = matches.length === 1 ? matches[0] : null
        const inSection = field && field.section ? field.section.label : undefined
        const usable = field && inSection === opts.section && SIMPLE_TYPES.includes(field.type) &&
          typeof field.value === 'string' && field.value !== ''
        results.push(usable ? { value: field.value } : await readOne(this, name))
      }
      return results
    }
  }
}

const SIMPLE_TYPES = ['CONCEALED', 'STRING']
// Keep one command line well under the OS argument limits.
const MAX_ASSIGNMENTS = 50
const MAX_ARG_BYTES = 64 * 1024

module.exports = { createOnePasswordAdapter, readOpRef }
