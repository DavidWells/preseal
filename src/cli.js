const fs = require('fs')
const path = require('path')
const { parseArgs } = require('util')
const { encrypt, decrypt, isEncrypted, versionOf, generateKey, normalizeKeys, latestVersion } = require('./crypto')
const {
  PACKAGE_NAME,
  detectFormat,
  findKeyFile,
  readKeyFile,
  createKeyFile,
  renderKeyFile,
  rotateKeyFile
} = require('./key-file')

// Loaded on first use. A command needs only a few of these, and loading them
// all (readline, child_process, every adapter) is about half the startup cost.
const lazy = {
  get readline() { return require('readline') },
  get adapters() { return require('./adapters') },
  get sources() { return require('./sources') },
  get seal() { return require('./seal') },
  get batch() { return require('./batch') },
  get dotenv() { return require('./dotenv') },
  get exec() { return require('./exec') }
}

/** @type {string} */
const HELP = `preseal: encrypt env vars before your host sees them

The ciphertext goes to your host (Netlify, AWS SSM, 1Password). The key lives
in a file in your repo. A leak of either one alone gives an attacker nothing.

Usage
  preseal init                         Create the key file (src/env-key.js)
  preseal set <NAME> --to <target>     Encrypt a value and store the ciphertext
  preseal push <.env file> --to <target>   Encrypt every value in a dotenv file
  preseal reseal <NAME> --to <target>  Encrypt a value already stored in a target, in place
  preseal check <NAME> --to <target>   Confirm a stored value decrypts with your key
  preseal rotate                       Add a new key version to the key file
  preseal encrypt                      Print the ciphertext for one value
  preseal decrypt [value]              Print the plaintext for one value
  preseal keygen                       Print a new key

Targets (--to, repeatable)
  netlify                   The linked Netlify site    --context --scope --secret --site
  netlify:<site>            A Netlify site by name or ID
  ssm:/my-app/prod          AWS SSM, /my-app/prod/<NAME>   --region --profile --ssm-type --kms-key-id
  op://Vault/Item           Fields on a 1Password item
  dotenv:.env.production    A dotenv file
  stdout                    Print NAME=value (default)

Where the plaintext comes from
  (nothing)                 Hidden prompt, or stdin when piped
  --from op://Vault/Item/field    1Password
  --from ssm:/path/to/param       AWS SSM
  --from env:NAME                 An environment variable
  --from file:path                A file
  NAME=<source>             Same sources, one per variable: set A=op://V/I/a B=op://V/I/b

Options
  -t, --to <target>         Where the ciphertext goes
  -f, --from <source>       Where the plaintext comes from
  -k, --key-file <path>     Key file, default src/env-key.* or ./env-key.*
      --file <path>         init: where to write the key file
      --format <cjs|esm|ts> init: module flavor, default detected
      --standalone          init: inline the decrypt code (no runtime dependency)
      --linked              init: import createEnv from ${PACKAGE_NAME}
      --print               init: print the module, write nothing
      --only <A,B*>         push: only these names
      --except <A,B*>       push: all but these names
      --dry-run             Show what would be written, write nothing
      --force               init: overwrite. reseal: re-encrypt current values too
      --cwd <dir>           Project directory; netlify, aws and op run there
  -h, --help
  -v, --version

Examples
  preseal set STRIPE_SECRET_KEY --to netlify --context production
  preseal set STRIPE_SECRET_KEY --from op://Eng/Stripe/secret --to ssm:/my-app/prod
  preseal push .env.production --to netlify --to op://Eng/my-app
  pbpaste | preseal encrypt
`

const OPTIONS = {
  to: { type: 'string', multiple: true, short: 't' },
  from: { type: 'string', short: 'f' },
  value: { type: 'string' },
  'key-file': { type: 'string', short: 'k' },
  cwd: { type: 'string' },
  context: { type: 'string', multiple: true, short: 'c' },
  scope: { type: 'string', multiple: true, short: 's' },
  secret: { type: 'boolean' },
  site: { type: 'string' },
  filter: { type: 'string' },
  region: { type: 'string' },
  profile: { type: 'string' },
  'ssm-type': { type: 'string' },
  'kms-key-id': { type: 'string' },
  tier: { type: 'string' },
  file: { type: 'string' },
  format: { type: 'string' },
  standalone: { type: 'boolean' },
  linked: { type: 'boolean' },
  print: { type: 'boolean' },
  force: { type: 'boolean' },
  only: { type: 'string' },
  except: { type: 'string' },
  'dry-run': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' }
}

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]*$/

/**
 * @typedef {object} CliIo
 * @property {(text: string) => void} [stdout]
 * @property {(text: string) => void} [stderr]
 * @property {import('./exec').Exec} [exec]
 * @property {Record<string, string | undefined>} [env]
 * @property {string} [cwd]
 * @property {boolean} [isTTY] - stdin is a terminal
 * @property {() => Promise<string>} [readStdin]
 * @property {(question: string) => Promise<string>} [prompt] - hidden prompt
 */

function readAllStdin() {
  return new Promise((resolve, reject) => {
    let data = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (chunk) => { data += chunk })
    process.stdin.on('end', () => resolve(data))
    process.stdin.on('error', reject)
  })
}

function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const rl = lazy.readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true })
    process.stderr.write(question)
    // Swallow the echo so the secret never reaches the screen or scrollback.
    Object.assign(rl, { _writeToOutput() {} })
    rl.on('SIGINT', () => {
      rl.close()
      process.stderr.write('\n')
      reject(new Error('preseal: cancelled'))
    })
    rl.question('', (answer) => {
      rl.close()
      process.stderr.write('\n')
      resolve(answer)
    })
  })
}

function splitList(value) {
  return (value || '').split(',').map((item) => item.trim()).filter(Boolean)
}

// A repeatable flag whose values may also be comma-separated.
function list(values) {
  return values ? values.flatMap(splitList) : undefined
}

const NETLIFY_WORDS = /^(production|deploy-preview|branch-deploy|dev|dev-server|branch:.+|builds|functions|runtime|post-processing)$/

// A quoted list of names ("A B C") or a typo would otherwise read as "is not set".
function assertNames(names) {
  const invalid = names.find((name) => !NAME_RE.test(name))
  if (invalid !== undefined) throw new Error(`preseal: "${invalid}" is not a valid variable name`)
}

// Where a value was read from, which can be narrower than where it is written.
function readFrom(adapter) {
  return adapter.readLabel || adapter.label
}

function isDirectory(dir) {
  try {
    return fs.statSync(dir).isDirectory()
  } catch (error) {
    return false
  }
}

function matcher(patterns) {
  const res = patterns.map((pattern) => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`))
  return (name) => res.some((re) => re.test(name))
}

/**
 * Run the CLI.
 * @param {string[]} argv - arguments after the binary name
 * @param {CliIo} [io] - injectable I/O, for tests and embedding
 * @returns {Promise<number>} exit code
 */
async function run(argv, io = {}) {
  const out = io.stdout || ((text) => process.stdout.write(text))
  const err = io.stderr || ((text) => process.stderr.write(text))
  const exec = io.exec || ((cmd, cmdArgs, opts) => lazy.exec.exec(cmd, cmdArgs, opts))
  const env = io.env || process.env
  const isTTY = io.isTTY !== undefined ? io.isTTY : Boolean(process.stdin.isTTY)
  const readStdin = io.readStdin || readAllStdin
  const prompt = io.prompt || promptHidden

  let flags
  let positionals
  try {
    const parsed = parseArgs({ args: argv, options: /** @type {any} */ (OPTIONS), allowPositionals: true, strict: true })
    flags = /** @type {Record<string, any>} */ (parsed.values)
    positionals = parsed.positionals
  } catch (error) {
    err(`preseal: ${error.message}\nRun preseal --help for usage.\n`)
    return 1
  }

  const cwd = path.resolve(io.cwd || process.cwd(), flags.cwd || '.')
  const command = positionals[0]
  const args = positionals.slice(1)
  const rel = (file) => path.relative(cwd, file) || file
  // A dry run writes nothing at all: no target, no key file, no package.json.
  const dryRun = Boolean(flags['dry-run'])

  if (flags.version) {
    out(`${JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version}\n`)
    return 0
  }
  if (flags.help || !command || command === 'help') {
    out(HELP)
    return 0
  }
  // The netlify, aws and op CLIs run in this directory, so it has to exist.
  if (flags.cwd && !isDirectory(cwd)) {
    err(`preseal: --cwd ${flags.cwd} is not a directory\n`)
    return 1
  }

  // The Netlify CLI takes `--context production deploy-preview`. Here that
  // would make `deploy-preview` a variable name, so catch it early.
  const stray = (flags.context || flags.scope) && args.find((arg) => NETLIFY_WORDS.test(arg))
  if (stray) {
    err(
      `preseal: "${stray}" looks like a --context or --scope value, not a variable name. ` +
      'Repeat the flag or use commas: --context production,deploy-preview\n'
    )
    return 1
  }

  /** Two lines of example code in the project's own module style. */
  function usageSnippet(file, format) {
    let spec = `./${rel(file).split(path.sep).join('/')}`
    if (format === 'cjs' || format === 'ts') spec = spec.replace(/\.(js|ts)$/, '')
    if (format === 'cjs') {
      return [`const { env } = require('${spec}')`, "const stripe = require('stripe')(env('STRIPE_SECRET_KEY'))"]
    }
    return [`import { env } from '${spec}'`, "const stripeKey = env('STRIPE_SECRET_KEY')"]
  }

  function chooseStandalone() {
    if (flags.standalone && flags.linked) throw new Error('preseal: pick one of --standalone and --linked')
    if (flags.standalone) return true
    if (flags.linked) return false
    // A generated file must run as is: only import the package when the app already depends on it.
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'))
      return !(pkg.dependencies && pkg.dependencies[PACKAGE_NAME])
    } catch (error) {
      return true
    }
  }

  function initKeyFile() {
    const created = createKeyFile({
      cwd,
      file: flags.file || flags['key-file'],
      format: flags.format,
      standalone: chooseStandalone(),
      force: flags.force,
      dryRun
    })
    if (dryRun) {
      err(`would create ${rel(created.file)} with a new key (v1)\n`)
      return created
    }
    err([
      `Created ${rel(created.file)} with a new key (v1).`,
      '',
      'Read secrets through it in server code:',
      '',
      ...usageSnippet(created.file, created.format).map((line) => `  ${line}`),
      '',
      `Commit ${rel(created.file)}. Keep the repo private, and never import the file from browser code.`,
      '',
      ''
    ].join('\n'))
    return created
  }

  /**
   * @param {{ create?: boolean }} [opts]
   * @returns {{ keys: Record<string, string>, file: string | null }}
   */
  function loadKeys(opts = {}) {
    const file = findKeyFile(cwd, flags['key-file'])
    if (file && fs.existsSync(file)) return { keys: readKeyFile(file), file }
    if (env.PRESEAL_KEY && !flags['key-file']) return { keys: normalizeKeys(env.PRESEAL_KEY), file: null }
    if (!opts.create) {
      throw new Error('preseal: no key file found. Run `preseal init` first, or pass --key-file <path>.')
    }
    const created = initKeyFile()
    return { keys: created.keys, file: created.file }
  }

  function targetOptions() {
    return {
      cwd,
      site: flags.site,
      context: list(flags.context),
      scope: list(flags.scope),
      secret: flags.secret,
      filter: flags.filter,
      region: flags.region,
      profile: flags.profile,
      ssmType: flags['ssm-type'],
      kmsKeyId: flags['kms-key-id'],
      tier: flags.tier,
      write: out
    }
  }

  function targets(fallback) {
    const specs = flags.to && flags.to.length ? flags.to : fallback
    if (!specs) throw new Error(`preseal: ${command} needs a target: --to netlify, --to ssm:/path or --to op://Vault/Item`)
    return specs.map((spec) => lazy.adapters.resolveTarget(spec, targetOptions(), { exec }))
  }

  const sourceIo = { exec, env, cwd, region: flags.region, profile: flags.profile }

  /** Read one plaintext value from --from, --value, stdin or a hidden prompt. */
  async function readValue(label) {
    if (flags.from && flags.value !== undefined) throw new Error('preseal: pick one of --from and --value')
    if (flags.from) return lazy.sources.readSource(flags.from, sourceIo)
    if (flags.value !== undefined) return flags.value
    if (isTTY) return prompt(`${label}: `)
    return (await readStdin()).replace(/\r?\n$/, '')
  }

  try {
    switch (command) {
      case 'keygen': {
        out(`${generateKey()}\n`)
        return 0
      }

      case 'init': {
        if (flags.print) {
          const format = flags.format || detectFormat(cwd)
          out(renderKeyFile({ keys: { v1: generateKey() }, format, standalone: chooseStandalone() }))
          return 0
        }
        const created = initKeyFile()
        if (dryRun) return 0
        err([
          'Next, encrypt a value and send the ciphertext to your host:',
          '',
          '  preseal set STRIPE_SECRET_KEY --to netlify',
          '  preseal set STRIPE_SECRET_KEY --from op://Vault/Stripe/secret --to ssm:/my-app/prod',
          '  preseal push .env.production --to netlify',
          ''
        ].join('\n'))
        if (!/createEnv/.test(created.source)) return 0
        try {
          const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'))
          if (pkg.dependencies && pkg.dependencies[PACKAGE_NAME]) return 0
        } catch (error) { /* no package.json */ }
        err(`The key file imports ${PACKAGE_NAME}. Add it to your dependencies: npm install ${PACKAGE_NAME}\n`)
        return 0
      }

      case 'rotate': {
        const { file, keys: current } = loadKeys()
        if (!file) throw new Error('preseal: rotate edits a key file, and none was found (PRESEAL_KEY is set instead)')
        if (dryRun) {
          err(`would add key v${Number(latestVersion(current).slice(1)) + 1} to ${rel(file)}\n`)
          return 0
        }
        const { version, keys } = rotateKeyFile(file)
        const previous = Object.keys(keys).filter((v) => v !== version)
        const one = previous.length === 1
        // "v1", "v1 and v2", "v1, v2 and v3"
        const old = one ? previous[0] : `${previous.slice(0, -1).join(', ')} and ${previous[previous.length - 1]}`
        err([
          `Added key ${version} to ${rel(file)}. New values are encrypted with ${version}; ${old} still ${one ? 'decrypts' : 'decrypt'}.`,
          '',
          'To finish the rotation:',
          '  1. Deploy, so the running app knows the new key.',
          '  2. Re-encrypt stored values:  preseal reseal <NAME...> --to <target>',
          `  3. Delete the ${old} ${one ? 'line' : 'lines'} from ${rel(file)} and deploy again.`,
          ''
        ].join('\n'))
        return 0
      }

      case 'encrypt': {
        // The ciphertext is the output, so the key has to outlive the run: a dry run cannot make one.
        const { keys } = loadKeys({ create: !dryRun })
        const value = args.length ? args.join(' ') : await readValue('Value to encrypt')
        if (!value) throw new Error('preseal: nothing to encrypt')
        out(`${isEncrypted(value) ? value : encrypt(value, keys)}\n`)
        return 0
      }

      case 'decrypt': {
        const { keys } = loadKeys()
        const value = (args[0] || await readValue('Value to decrypt')).trim()
        if (!isEncrypted(value)) throw new Error('preseal: that value is not encrypted (no enc:vN: prefix)')
        out(`${decrypt(value, keys)}\n`)
        return 0
      }

      case 'set': {
        if (!args.length) throw new Error('preseal: set needs a variable name: preseal set STRIPE_SECRET_KEY --to netlify')
        const pairs = args.map((arg) => {
          const eq = arg.indexOf('=')
          const name = eq === -1 ? arg : arg.slice(0, eq)
          if (!NAME_RE.test(name)) throw new Error(`preseal: "${name}" is not a valid variable name`)
          return { name, inline: eq === -1 ? undefined : arg.slice(eq + 1) }
        })
        const bare = pairs.filter((pair) => pair.inline === undefined)
        if (bare.length > 1 && (flags.from || flags.value !== undefined || !isTTY)) {
          throw new Error('preseal: one value was given for several names. Use NAME=<source> pairs, or `preseal push <file>`.')
        }
        const adapters = targets(['stdout'])
        const { keys } = loadKeys({ create: true })

        const values = {}
        for (const pair of pairs) {
          if (pair.inline === undefined) values[pair.name] = await readValue(pair.name)
          else values[pair.name] = lazy.sources.isSourceSpec(pair.inline) ? await lazy.sources.readSource(pair.inline, sourceIo) : pair.inline
          if (!values[pair.name]) throw new Error(`preseal: ${pair.name} has no value to encrypt`)
        }
        await sealAndReport(values, keys, adapters)
        return 0
      }

      case 'push': {
        if (args.length !== 1) throw new Error('preseal: push needs one dotenv file: preseal push .env.production --to netlify')
        const file = path.resolve(cwd, args[0])
        let text
        try {
          text = fs.readFileSync(file, 'utf8')
        } catch (error) {
          throw new Error(`preseal: cannot read ${args[0]}`)
        }
        const all = lazy.dotenv.parseDotenv(text)
        const only = splitList(flags.only)
        const except = splitList(flags.except)
        const keep = only.length ? matcher(only) : () => true
        const drop = except.length ? matcher(except) : () => false
        const values = {}
        const skipped = []
        for (const name of Object.keys(all)) {
          if (!keep(name) || drop(name)) continue
          if (all[name] === '') skipped.push(name)
          else values[name] = all[name]
        }
        if (!Object.keys(values).length) throw new Error(`preseal: no values to push from ${args[0]}`)
        const adapters = targets()
        const { keys } = loadKeys({ create: true })
        await sealAndReport(values, keys, adapters)
        if (skipped.length) err(`Skipped (empty): ${skipped.join(', ')}\n`)
        return 0
      }

      case 'check': {
        if (!args.length) throw new Error('preseal: check needs a variable name: preseal check STRIPE_SECRET_KEY --to netlify')
        assertNames(args)
        const adapters = targets()
        const { keys } = loadKeys()
        let failed = 0
        for (const adapter of adapters) {
          if (!adapter.get) throw new Error(`preseal: the ${adapter.name} target cannot be read back`)
          const results = await lazy.batch.readMany(adapter, args)
          args.forEach((name, i) => {
            let problem
            let version
            try {
              if (results[i].error) throw results[i].error
              const stored = results[i].value
              version = versionOf(stored)
              if (stored === undefined || stored === '') problem = 'is not set'
              else if (!version) problem = 'is stored as plaintext'
              else decrypt(stored, keys)
            } catch (error) {
              problem = error.message.replace(/^preseal: /, '')
            }
            if (problem) failed++
            err(problem
              ? `✖ ${name} in ${readFrom(adapter)}: ${problem}\n`
              : `✔ ${name} in ${readFrom(adapter)}: decrypts with key ${version}\n`)
          })
        }
        return failed ? 1 : 0
      }

      case 'reseal': {
        if (!args.length) throw new Error('preseal: reseal needs a variable name: preseal reseal STRIPE_SECRET_KEY --to netlify')
        assertNames(args)
        const adapters = targets()
        const { keys } = loadKeys({ create: true })
        const latest = latestVersion(keys)
        // A name given twice has to see its own first write, so those go one at a time.
        const groups = new Set(args).size === args.length ? [args] : args.map((name) => [name])
        for (const adapter of adapters) {
          if (!adapter.get) throw new Error(`preseal: the ${adapter.name} target cannot be read back`)
          for (const names of groups) {
            const results = await lazy.batch.readMany(adapter, names)
            // Plan every name up to the first one that cannot be resealed.
            /** @type {{ line: string, entry?: [string, string] }[]} */
            const steps = []
            let failure = null
            for (let i = 0; i < names.length && !failure; i++) {
              const name = names[i]
              try {
                if (results[i].error) throw results[i].error
                const stored = results[i].value
                if (stored === undefined || stored === '') throw new Error(`preseal: ${name} is not set in ${readFrom(adapter)}`)
                const from = versionOf(stored)
                if (from === latest && !flags.force) {
                  steps.push({ line: `- ${name} in ${readFrom(adapter)}: already encrypted with ${latest}\n` })
                  continue
                }
                const next = encrypt(decrypt(stored, keys), keys, { version: latest })
                steps.push({
                  line: `${dryRun ? 'would write' : '✔'} ${name} in ${adapter.label}: ${from || 'plaintext'} → ${latest}\n`,
                  entry: dryRun ? undefined : [name, next]
                })
              } catch (error) {
                failure = error
              }
            }
            // Report in the order given: a line prints once everything before it is stored.
            const writes = steps.filter((step) => step.entry)
            let printed = 0
            let stored = 0
            const printUpTo = (end) => { while (printed < end) err(steps[printed++].line) }
            try {
              await lazy.batch.writeMany(adapter, writes.map((step) => step.entry), () => printUpTo(steps.indexOf(writes[stored++]) + 1))
            } catch (error) {
              printUpTo(steps.indexOf(writes[stored]))
              throw error
            }
            printUpTo(steps.length)
            if (failure) throw failure
          }
        }
        return 0
      }

      default:
        throw new Error(`preseal: unknown command "${command}". Run preseal --help for usage.`)
    }
  } catch (error) {
    err(`${/^preseal: /.test(error.message) ? '' : 'preseal: '}${error.message}\n`)
    return 1
  }

  async function sealAndReport(values, keys, adapters) {
    return lazy.seal.seal({
      values,
      keys,
      targets: adapters,
      dryRun,
      onWrite(event) {
        if (event.target === 'stdout' && !dryRun) return
        err(`${dryRun ? 'would write' : '✔'} ${event.name} → ${event.label}  (key ${event.version})\n`)
      }
    })
  }
}

module.exports = { run, HELP }
