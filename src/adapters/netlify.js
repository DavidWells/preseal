const { exec: defaultExec } = require('../exec')
const { readOne } = require('../batch')

/**
 * Netlify environment variables, through the `netlify` CLI (uses its login,
 * or NETLIFY_AUTH_TOKEN from the environment).
 *
 * @param {object} [opts]
 * @param {string} [opts.site] - site name or ID, default: the linked site
 * @param {string[]} [opts.context] - deploy contexts, default: all
 * @param {string[]} [opts.scope] - scopes (builds, functions, runtime, post-processing), default: all
 * @param {boolean} [opts.secret] - mark the variable as a Netlify secret (write-only)
 * @param {string} [opts.filter] - monorepo app name
 * @param {{ exec?: import('../exec').Exec }} [deps]
 * @returns {import('./index').Adapter}
 */
function createNetlifyAdapter(opts = {}, deps = {}) {
  const exec = deps.exec || defaultExec
  const context = opts.context || []
  const scope = opts.scope || []
  if (opts.secret && (!context.length || context.includes('dev'))) {
    throw new Error(
      'preseal: a Netlify secret needs a non-dev --context (production, deploy-preview, branch-deploy or branch:<name>)'
    )
  }

  // With no linked site the Netlify CLI prints this and still exits 0.
  function assertLinked(stdout) {
    if (/No (project|site) id found/i.test(stdout)) {
      throw new Error('preseal: no Netlify site is linked in this folder. Run `netlify link`, or pass --site <name-or-id>.')
    }
  }

  function common() {
    const args = []
    if (opts.site) args.push('--site', opts.site)
    if (opts.filter) args.push('--filter', opts.filter)
    return args
  }

  const where = [
    opts.site ? `site ${opts.site}` : 'linked site',
    context.length ? `context ${context.join(', ')}` : 'all contexts',
    scope.length ? `scope ${scope.join(', ')}` : null,
    opts.secret ? 'secret' : null
  ].filter(Boolean).join(', ')

  // A read resolves one context (dev unless told otherwise) and one scope.
  const readWhere = [
    opts.site ? `site ${opts.site}` : 'linked site',
    `context ${context[0] || 'dev'}`,
    scope.length ? `scope ${scope[0]}` : null
  ].filter(Boolean).join(', ')

  return {
    name: 'netlify',
    label: `Netlify (${where})`,
    readLabel: `Netlify (${readWhere})`,
    // Each variable is its own API resource, so a few can be written at once.
    concurrency: WRITE_CONCURRENCY,
    async set(name, value) {
      // Positionals first: --context and --scope are variadic and would swallow them.
      const args = ['env:set', name, value, '--force']
      if (context.length) args.push('--context', ...context)
      if (scope.length) args.push('--scope', ...scope)
      if (opts.secret) args.push('--secret')
      const { stdout } = await exec('netlify', args.concat(common()))
      assertLinked(stdout)
    },
    async get(name) {
      const args = ['env:get', name, '--json']
      if (context.length) args.push('--context', context[0])
      if (scope.length) args.push('--scope', scope[0])
      const { stdout } = await exec('netlify', args.concat(common()))
      assertLinked(stdout)
      const text = stdout.trim()
      let value
      try {
        const parsed = JSON.parse(text)
        if (parsed && typeof parsed === 'object') value = parsed[name]
        else if (typeof parsed === 'string') value = parsed
      } catch (err) {
        value = text || undefined
      }
      return unmasked(name, value)
    },
    // One `env:list` instead of one `env:get` per name. Both commands resolve
    // values the same way; `env:list` only leaves out a few sources and keeps
    // empty values, so anything it doesn't answer clearly goes through `get`.
    async getMany(names) {
      let listed = null
      try {
        const args = ['env:list', '--json']
        if (context.length) args.push('--context', context[0])
        if (scope.length) args.push('--scope', scope[0])
        const { stdout } = await exec('netlify', args.concat(common()))
        assertLinked(stdout)
        const parsed = JSON.parse(stdout)
        if (parsed && typeof parsed === 'object') listed = parsed
      } catch (err) {
        listed = null
      }
      const results = []
      for (const name of names) {
        const value = listed ? listed[name] : undefined
        if (typeof value !== 'string' || !value) {
          results.push(await readOne(this, name))
          continue
        }
        try {
          results.push({ value: unmasked(name, value) })
        } catch (error) {
          results.push({ error })
        }
      }
      return results
    }
  }
}

const WRITE_CONCURRENCY = 4

// A secret reads back masked (`****************5Q==`). Treating that as the
// value would let `reseal` encrypt the mask and overwrite the real secret.
function unmasked(name, value) {
  if (typeof value === 'string' && /^\*{4,}/.test(value)) {
    throw new Error(`preseal: ${name} is a Netlify secret. Netlify masks its value, so it cannot be read back to check or reseal.`)
  }
  return value
}

module.exports = { createNetlifyAdapter }
