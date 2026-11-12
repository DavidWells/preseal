const { exec: defaultExec, execIn } = require('../exec')
const { createNetlifyAdapter } = require('./netlify')
const { createSsmAdapter } = require('./ssm')
const { createOnePasswordAdapter, readOpRef } = require('./onepassword')
const { createDotenvAdapter } = require('./dotenv')

/**
 * @typedef {object} Adapter
 * The port a secret store implements. `set` is all a store needs; `get`
 * enables `preseal check` and `preseal reseal`.
 * @property {string} name
 * @property {string} [label] - human description of where values go
 * @property {string} [readLabel] - where values are read from, when that is narrower than `label`
 * @property {(name: string, value: string) => Promise<void>} set
 * @property {(name: string) => Promise<string | undefined>} [get]
 * @property {(names: string[]) => Promise<import('../batch').ReadResult[]>} [getMany] - read many names in one call; one result per name, in order, and it never throws
 * @property {(entries: [string, string][]) => Promise<void>} [setMany] - write many [name, value] pairs in one call
 * @property {number} [concurrency] - how many `set` calls may run at once (default 1)
 */

/**
 * @typedef {object} TargetOptions
 * @property {string} [cwd] - where the netlify, aws and op CLIs run, and where dotenv files resolve
 * @property {string} [site] - netlify
 * @property {string[]} [context] - netlify
 * @property {string[]} [scope] - netlify
 * @property {boolean} [secret] - netlify
 * @property {string} [filter] - netlify
 * @property {string} [region] - ssm
 * @property {string} [profile] - ssm
 * @property {string} [ssmType] - ssm
 * @property {string} [kmsKeyId] - ssm
 * @property {string} [tier] - ssm
 * @property {(line: string) => void} [write] - stdout target sink
 */

/**
 * Prints `NAME=value` lines.
 * @param {{ write?: (line: string) => void }} [opts]
 * @returns {Adapter}
 */
function createStdoutAdapter(opts = {}) {
  const write = opts.write || ((line) => process.stdout.write(line))
  return {
    name: 'stdout',
    label: 'stdout',
    async set(name, value) {
      write(`${name}=${value}\n`)
    }
  }
}

/**
 * Turn a target spec into an adapter.
 *
 *   netlify                    the linked Netlify site
 *   netlify:my-site            a site by name or ID
 *   ssm:/my-app/prod           SSM parameters under a path
 *   op://Vault/Item            fields on a 1Password item
 *   op://Vault/Item/Section    fields in a section of the item
 *   dotenv:.env.production     a dotenv file
 *   stdout                     print NAME=value
 *
 * An object with a `set` function is used as a custom adapter.
 *
 * @param {string | Adapter} spec
 * @param {TargetOptions} [opts]
 * @param {{ exec?: import('../exec').Exec }} [deps]
 * @returns {Adapter}
 */
function resolveTarget(spec, opts = {}, deps = {}) {
  if (spec && typeof spec === 'object') {
    if (typeof spec.set !== 'function') throw new Error('preseal: a custom adapter needs a set(name, value) function')
    return spec
  }
  if (typeof spec !== 'string' || !spec) throw new Error('preseal: empty target')

  if (spec === 'stdout' || spec === '-') return createStdoutAdapter({ write: opts.write })

  // CLIs run in the project directory when one is given.
  if (opts.cwd) deps = { exec: execIn(deps.exec || defaultExec, opts.cwd) }

  if (spec === 'netlify' || spec.startsWith('netlify:')) {
    return createNetlifyAdapter({
      site: spec.slice('netlify:'.length) || opts.site,
      context: opts.context,
      scope: opts.scope,
      secret: opts.secret,
      filter: opts.filter
    }, deps)
  }

  if (spec.startsWith('ssm:')) {
    return createSsmAdapter({
      path: spec.slice('ssm:'.length),
      region: opts.region,
      profile: opts.profile,
      type: opts.ssmType,
      kmsKeyId: opts.kmsKeyId,
      tier: opts.tier
    }, deps)
  }

  if (spec.startsWith('op://')) {
    const [vault, item, section, extra] = spec.slice('op://'.length).split('/')
    if (!vault || !item || extra !== undefined) {
      throw new Error(`preseal: 1Password targets look like op://Vault/Item or op://Vault/Item/Section (got ${spec})`)
    }
    return createOnePasswordAdapter({ vault, item, section }, deps)
  }

  if (spec.startsWith('dotenv:')) {
    return createDotenvAdapter({ file: spec.slice('dotenv:'.length), cwd: opts.cwd })
  }

  throw new Error(
    `preseal: unknown target "${spec}". Use netlify, netlify:<site>, ssm:/path, op://Vault/Item, dotenv:<file> or stdout`
  )
}

module.exports = {
  resolveTarget,
  createNetlifyAdapter,
  createSsmAdapter,
  createOnePasswordAdapter,
  createDotenvAdapter,
  createStdoutAdapter,
  readOpRef
}
