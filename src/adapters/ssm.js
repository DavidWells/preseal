const { exec: defaultExec } = require('../exec')
const { readOne, eachLimit } = require('../batch')

/**
 * AWS SSM Parameter Store, through the `aws` CLI (uses its credential chain).
 *
 * `path` is a prefix (`/my-app/prod` → `/my-app/prod/STRIPE_SECRET_KEY`), or a
 * template with `{name}` when the parameter name is shaped differently
 * (`/my-app/{name}/prod`).
 *
 * @param {object} opts
 * @param {string} opts.path
 * @param {string} [opts.region]
 * @param {string} [opts.profile]
 * @param {string} [opts.type] - SecureString (default), or String
 * @param {string} [opts.kmsKeyId] - KMS key for SecureString, default: the account's aws/ssm key
 * @param {string} [opts.tier] - Standard, Advanced or Intelligent-Tiering
 * @param {{ exec?: import('../exec').Exec }} [deps]
 * @returns {import('./index').Adapter}
 */
function createSsmAdapter(opts, deps = {}) {
  const exec = deps.exec || defaultExec
  if (!opts || !opts.path || !opts.path.startsWith('/')) {
    throw new Error('preseal: the SSM target needs an absolute path, like ssm:/my-app/prod')
  }
  const type = opts.type || 'SecureString'

  function paramName(name) {
    if (opts.path.includes('{name}')) return opts.path.replace(/\{name\}/g, name)
    return `${opts.path.replace(/\/+$/, '')}/${name}`
  }

  function common() {
    const args = []
    if (opts.region) args.push('--region', opts.region)
    if (opts.profile) args.push('--profile', opts.profile)
    return args
  }

  return {
    name: 'ssm',
    // Each parameter is independent, so a few can be written at once.
    concurrency: WRITE_CONCURRENCY,
    label: `AWS SSM (${paramName('<NAME>')}${opts.region ? `, ${opts.region}` : ''}, ${type})`,
    async set(name, value) {
      const args = ['ssm', 'put-parameter', '--name', paramName(name), '--value', value, '--type', type, '--overwrite']
      if (opts.kmsKeyId && type === 'SecureString') args.push('--key-id', opts.kmsKeyId)
      if (opts.tier) args.push('--tier', opts.tier)
      await exec('aws', args.concat(common()))
    },
    async get(name) {
      const args = [
        'ssm', 'get-parameter', '--name', paramName(name), '--with-decryption',
        '--query', 'Parameter.Value', '--output', 'text'
      ]
      try {
        const { stdout } = await exec('aws', args.concat(common()))
        return stdout.replace(/\r?\n$/, '')
      } catch (err) {
        // A parameter that doesn't exist is "not set", not a failure.
        if (/ParameterNotFound/.test(err.message)) return undefined
        throw err
      }
    },
    // `get-parameters` takes ten names per call. A name it doesn't return,
    // or a chunk that fails, goes through `get` so errors read the same.
    async getMany(names) {
      const params = Array.from(new Set(names.map(paramName)))
      /** @type {Map<string, string>} */
      const found = new Map()
      const chunks = []
      for (let i = 0; i < params.length; i += GET_PARAMETERS_MAX) chunks.push(params.slice(i, i + GET_PARAMETERS_MAX))
      await eachLimit(chunks, READ_CONCURRENCY, async (chunk) => {
        const args = ['ssm', 'get-parameters', '--names', ...chunk, '--with-decryption', '--output', 'json']
        try {
          const { stdout } = await exec('aws', args.concat(common()))
          for (const param of JSON.parse(stdout).Parameters || []) {
            if (typeof param.Value === 'string') found.set(param.Name, param.Value)
          }
        } catch (err) { /* this chunk falls back to one get per name */ }
      })
      const results = []
      for (const name of names) {
        const value = found.get(paramName(name))
        results.push(value === undefined ? await readOne(this, name) : { value })
      }
      return results
    }
  }
}

const GET_PARAMETERS_MAX = 10
const READ_CONCURRENCY = 4
const WRITE_CONCURRENCY = 4

module.exports = { createSsmAdapter }
