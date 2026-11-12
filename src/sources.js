const fs = require('fs')
const path = require('path')
const { exec: defaultExec, execIn } = require('./exec')
const { readOpRef } = require('./adapters/onepassword')

const SOURCE_RE = /^(op:\/\/|ssm:\/|env:|file:)/

/**
 * True when a string names a place to read a value from, not a literal value.
 * @param {string} spec
 * @returns {boolean}
 */
function isSourceSpec(spec) {
  return SOURCE_RE.test(spec)
}

/**
 * Read a plaintext value from where it already lives, so it never passes
 * through argv or shell history.
 *
 *   op://Vault/Item/field    1Password (op-stash when installed, else op)
 *   ssm:/path/to/param       AWS SSM, decrypted
 *   env:NAME                 an environment variable of this process
 *   file:path                a file (one trailing newline is dropped)
 *
 * @param {string} spec
 * @param {object} [io]
 * @param {import('./exec').Exec} [io.exec]
 * @param {Record<string, string | undefined>} [io.env]
 * @param {string} [io.cwd]
 * @param {string} [io.region] - ssm
 * @param {string} [io.profile] - ssm
 * @returns {Promise<string>}
 */
async function readSource(spec, io = {}) {
  const exec = execIn(io.exec || defaultExec, io.cwd)

  if (spec.startsWith('op://')) return readOpRef(spec, exec)

  if (spec.startsWith('ssm:')) {
    const args = [
      'ssm', 'get-parameter', '--name', spec.slice('ssm:'.length), '--with-decryption',
      '--query', 'Parameter.Value', '--output', 'text'
    ]
    if (io.region) args.push('--region', io.region)
    if (io.profile) args.push('--profile', io.profile)
    const { stdout } = await exec('aws', args)
    return stdout.replace(/\r?\n$/, '')
  }

  if (spec.startsWith('env:')) {
    const name = spec.slice('env:'.length)
    const value = (io.env || process.env)[name]
    if (value === undefined) throw new Error(`preseal: environment variable ${name} is not set`)
    return value
  }

  if (spec.startsWith('file:')) {
    const file = path.resolve(io.cwd || process.cwd(), spec.slice('file:'.length))
    return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, '')
  }

  throw new Error(`preseal: unknown source "${spec}". Use op://Vault/Item/field, ssm:/path, env:NAME or file:path`)
}

module.exports = { readSource, isSourceSpec }
