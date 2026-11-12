const { test } = require('uvu')
const assert = require('uvu/assert')
const fs = require('fs')
const path = require('path')
const { execFileSync, spawnSync } = require('child_process')
const { run } = require('../src/cli')
const { decrypt, encrypt, isEncrypted } = require('../src/crypto')
const { readKeyFile, findKeyFile } = require('../src/key-file')
const { parseDotenv } = require('../src/dotenv')
const { tmpProject, fakeExec } = require('./helpers')

const BIN = path.resolve(__dirname, '../bin/preseal.js')

/** Run the CLI in process with recording I/O. */
async function cli(argv, opts = {}) {
  let stdout = ''
  let stderr = ''
  const exec = opts.exec || fakeExec()
  const prompts = []
  const code = await run(argv, {
    cwd: opts.cwd,
    env: opts.env || {},
    exec,
    isTTY: Boolean(opts.tty),
    readStdin: async () => opts.stdin || '',
    prompt: async (question) => {
      prompts.push(question)
      return (opts.answers || []).shift() || ''
    },
    stdout: (text) => { stdout += text },
    stderr: (text) => { stderr += text }
  })
  return { code, stdout, stderr, exec, prompts }
}

function keysOf(dir) {
  return readKeyFile(findKeyFile(dir))
}

test('help and version', async () => {
  assert.match((await cli(['--help'])).stdout, /encrypt env vars before your host sees them/)
  assert.match((await cli([])).stdout, /Usage/)
  assert.is((await cli(['--version'])).stdout.trim(), require('../package.json').version)
})

test('unknown flags and commands fail with a pointer to help', async () => {
  const flag = await cli(['set', 'A', '--nope'])
  assert.is(flag.code, 1)
  assert.match(flag.stderr, /--help/)
  const command = await cli(['frobnicate'], { cwd: tmpProject() })
  assert.is(command.code, 1)
  assert.match(command.stderr, /unknown command "frobnicate"/)
})

test('keygen prints a usable key', async () => {
  const { stdout } = await cli(['keygen'])
  assert.is(Buffer.from(stdout.trim(), 'base64').length, 32)
})

test('init writes a standalone key file and explains how to use it', async () => {
  const dir = tmpProject({ 'package.json': { name: 'app' }, 'src/index.js': '' })
  const result = await cli(['init'], { cwd: dir })
  assert.is(result.code, 0)
  assert.is(result.stdout, '')
  assert.match(result.stderr, /Created src\/env-key.js with a new key \(v1\)/)
  assert.match(result.stderr, /const \{ env \} = require\('.\/src\/env-key'\)/)
  assert.not.match(result.stderr, keysOf(dir).v1)
  const source = fs.readFileSync(path.join(dir, 'src/env-key.js'), 'utf8')
  assert.match(source, "require('crypto')")
  assert.not.match(source, 'createEnv')
})

test('init links to the package when the app already depends on it', async () => {
  const dir = tmpProject({ 'package.json': { type: 'module', dependencies: { 'preseal': '^0.0.1' } } })
  const result = await cli(['init'], { cwd: dir })
  const source = fs.readFileSync(path.join(dir, 'env-key.js'), 'utf8')
  assert.match(source, "import { createEnv } from 'preseal'")
  assert.match(result.stderr, /import \{ env \} from '.\/env-key.js'/)
  assert.not.match(result.stderr, /npm install/)
})

test('init --linked without the dependency says to install it', async () => {
  const dir = tmpProject({ 'package.json': {} })
  const result = await cli(['init', '--linked'], { cwd: dir })
  assert.match(result.stderr, /npm install preseal\n/)
})

test('init shows example code in the module style of the key file', async () => {
  const cjs = await cli(['init'], { cwd: tmpProject({ 'package.json': {} }) })
  assert.match(cjs.stderr, "const stripe = require('stripe')(env('STRIPE_SECRET_KEY'))")

  const esm = await cli(['init'], { cwd: tmpProject({ 'package.json': { type: 'module' } }) })
  assert.match(esm.stderr, "import { env } from './env-key.js'")
  assert.match(esm.stderr, "const stripeKey = env('STRIPE_SECRET_KEY')")
  assert.not.match(esm.stderr, 'require(')

  const ts = await cli(['init'], { cwd: tmpProject({ 'package.json': {}, 'tsconfig.json': {} }) })
  assert.match(ts.stderr, "import { env } from './env-key'")
  assert.not.match(ts.stderr, 'require(')
})

test('hints name the command to run', () => {
  assert.throws(() => readKeyFile(path.join(tmpProject(), 'missing.js')), /npx preseal init$/)
  assert.throws(() => encrypt('value', 'too-short'), /npx preseal keygen$/)
  assert.throws(() => encrypt('value', { v1: '' }), /npx preseal keygen$/)
})

test('init detects typescript and honors --file and --format', async () => {
  const ts = tmpProject({ 'package.json': {}, 'tsconfig.json': {} })
  await cli(['init'], { cwd: ts })
  assert.match(fs.readFileSync(path.join(ts, 'env-key.ts'), 'utf8'), /const ENV_KEYS: Record<string, string> = \{/)

  const custom = tmpProject({ 'package.json': {} })
  const result = await cli(['init', '--file', 'config/key.mjs', '--format', 'esm'], { cwd: custom })
  assert.is(result.code, 0)
  assert.match(fs.readFileSync(path.join(custom, 'config/key.mjs'), 'utf8'), /export \{ env, ENV_KEYS \}/)
  assert.is(findKeyFile(custom), path.join(custom, 'config/key.mjs'))
})

test('init refuses to overwrite an existing key file', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const before = keysOf(dir).v1
  const again = await cli(['init'], { cwd: dir })
  assert.is(again.code, 1)
  assert.match(again.stderr, /already exists/)
  assert.is(keysOf(dir).v1, before)
})

test('init --print writes nothing and prints the module', async () => {
  const dir = tmpProject({ 'package.json': {} })
  const result = await cli(['init', '--print'], { cwd: dir })
  assert.match(result.stdout, /const ENV_KEYS = \{/)
  assert.is(findKeyFile(dir), null)
})

test('set reads stdin and prints NAME=ciphertext by default', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const result = await cli(['set', 'STRIPE_SECRET_KEY'], { cwd: dir, stdin: 'sk_live_abc123\n' })
  assert.is(result.code, 0)
  const [name, value] = result.stdout.trim().split(/=(.*)/s)
  assert.is(name, 'STRIPE_SECRET_KEY')
  assert.is(decrypt(value, keysOf(dir)), 'sk_live_abc123')
})

test('set creates the key file on first use', async () => {
  const dir = tmpProject({ 'package.json': {} })
  const result = await cli(['set', 'A', '--to', 'netlify'], { cwd: dir, stdin: 'alpha' })
  assert.is(result.code, 0)
  assert.match(result.stderr, /Created env-key.js with a new key/)
  assert.is(decrypt(result.exec.calls[0].args[2], keysOf(dir)), 'alpha')
})

test('set --to netlify sends only ciphertext, with the netlify flags', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const result = await cli(['set', 'STRIPE_SECRET_KEY', '--to', 'netlify', '--context', 'production', '--scope', 'functions', '--site', 'my-site'], {
    cwd: dir,
    stdin: 'sk_live_abc123'
  })
  assert.is(result.code, 0)
  const call = result.exec.calls[0]
  assert.is(call.cmd, 'netlify')
  assert.equal(call.args.slice(0, 2), ['env:set', 'STRIPE_SECRET_KEY'])
  assert.is(decrypt(call.args[2], keysOf(dir)), 'sk_live_abc123')
  assert.equal(call.args.slice(3), ['--force', '--context', 'production', '--scope', 'functions', '--site', 'my-site'])
  assert.not.match(JSON.stringify(result.exec.calls), 'sk_live_abc123')
  assert.match(result.stderr, /✔ STRIPE_SECRET_KEY → Netlify \(site my-site, context production, scope functions\) {2}\(key v1\)/)
  assert.is(result.stdout, '')
})

test('--context and --scope take commas or repeats, and reject Netlify CLI style', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const ok = await cli(['set', 'A', '--to', 'netlify', '--scope', 'builds,functions', '--context', 'production', '--context', 'deploy-preview'], {
    cwd: dir,
    stdin: 'value'
  })
  assert.is(ok.code, 0)
  assert.equal(ok.exec.calls[0].args.slice(3), ['--force', '--context', 'production', 'deploy-preview', '--scope', 'builds', 'functions'])

  const bad = await cli(['set', 'A', '--to', 'netlify', '--scope', 'builds', 'functions'], { cwd: dir, stdin: 'value' })
  assert.is(bad.code, 1)
  assert.match(bad.stderr, /"functions" looks like a --context or --scope value/)
  assert.is(bad.exec.calls.length, 0)
})

test('reseal refuses a Netlify secret instead of encrypting its mask', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const result = await cli(['reseal', 'A', '--to', 'netlify', '--context', 'production'], {
    cwd: dir,
    exec: fakeExec(() => JSON.stringify({ A: '****************5Q==' }))
  })
  assert.is(result.code, 1)
  assert.match(result.stderr, /A is a Netlify secret/)
  assert.equal(result.exec.calls.map((call) => call.args[0]), ['env:get'])
})

test('set prompts without echo on a terminal', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const result = await cli(['set', 'A', 'B', '--to', 'ssm:/app/prod'], { cwd: dir, tty: true, answers: ['alpha', 'beta'] })
  assert.is(result.code, 0)
  assert.equal(result.prompts, ['A: ', 'B: '])
  assert.equal(result.exec.calls.map((call) => call.args[3]), ['/app/prod/A', '/app/prod/B'])
  assert.is(decrypt(result.exec.calls[1].args[5], keysOf(dir)), 'beta')
})

test('set --from op:// reads through op-stash and writes to several targets', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const exec = fakeExec((cmd) => (cmd === 'op-stash' ? 'sk_from_1password\n' : ''))
  const result = await cli(['set', 'STRIPE_SECRET_KEY', '--from', 'op://Eng/Stripe/secret', '--to', 'netlify', '--to', 'ssm:/app/prod', '--to', 'op://Eng/my-app', '--region', 'us-east-1'], { cwd: dir, exec })
  assert.is(result.code, 0)
  assert.equal(exec.calls.map((call) => `${call.cmd} ${call.args.slice(0, 2).join(' ')}`), [
    'op-stash read op://Eng/Stripe/secret',
    'netlify env:set STRIPE_SECRET_KEY',
    'aws ssm put-parameter',
    'op item edit'
  ])
  const sent = [exec.calls[1].args[2], exec.calls[2].args[5], exec.calls[3].args[5].split(/=(.*)/s)[1]]
  assert.is(new Set(sent).size, 1)
  assert.is(decrypt(sent[0], keysOf(dir)), 'sk_from_1password')
  assert.equal(exec.calls[2].args.slice(-2), ['--region', 'us-east-1'])
})

test('set NAME=<source> pairs read each value from its own place', async () => {
  const dir = tmpProject({ 'package.json': {}, 'db.txt': 'postgres://u:p@h/db\n' })
  await cli(['init'], { cwd: dir })
  const exec = fakeExec((cmd, args) => (cmd === 'op-stash' ? `value-of-${args[1].split('/').pop()}\n` : ''))
  const result = await cli(['set', 'A=op://V/I/a', 'B=env:LOCAL_B', 'C=file:db.txt', 'D=literal=value', '--to', 'dotenv:.env.sealed'], {
    cwd: dir,
    exec,
    env: { LOCAL_B: 'bee' }
  })
  assert.is(result.code, 0)
  const sealed = parseDotenv(fs.readFileSync(path.join(dir, '.env.sealed'), 'utf8'))
  const keys = keysOf(dir)
  assert.equal(Object.keys(sealed), ['A', 'B', 'C', 'D'])
  assert.ok(Object.values(sealed).every(isEncrypted))
  assert.equal(Object.values(sealed).map((value) => decrypt(value, keys)), ['value-of-a', 'bee', 'postgres://u:p@h/db', 'literal=value'])
})

test('set rejects bad input before touching a target', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const cases = [
    [['set'], /set needs a variable name/],
    [['set', '1BAD', '--to', 'netlify'], /not a valid variable name/],
    [['set', 'A', 'B', '--to', 'netlify'], /one value was given for several names/],
    [['set', 'A', '--to', 'vercel'], /unknown target "vercel"/],
    [['set', 'A', '--to', 'netlify', '--from', 'env:X', '--value', 'y'], /pick one of --from and --value/],
    [['set', 'A', '--to', 'netlify'], /A has no value to encrypt/]
  ]
  for (const [argv, pattern] of cases) {
    const result = await cli(argv, { cwd: dir, stdin: '' })
    assert.is(result.code, 1, argv.join(' '))
    assert.match(result.stderr, pattern)
    assert.is(result.exec.calls.length, 0, argv.join(' '))
  }
})

test('--dry-run encrypts but writes nothing', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const result = await cli(['set', 'A', '--to', 'netlify', '--to', 'dotenv:.env.out', '--dry-run'], { cwd: dir, stdin: 'alpha' })
  assert.is(result.code, 0)
  assert.is(result.exec.calls.length, 0)
  assert.not.ok(fs.existsSync(path.join(dir, '.env.out')))
  assert.match(result.stderr, /would write A → Netlify/)
})

test('a failing target reports the tool error and exits 1', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const exec = fakeExec(() => ({ code: 1, stderr: 'AccessDeniedException: not authorized to perform ssm:PutParameter' }))
  const result = await cli(['set', 'A', '--to', 'ssm:/app'], { cwd: dir, exec, stdin: 'alpha' })
  assert.is(result.code, 1)
  assert.match(result.stderr, /AccessDeniedException/)
  assert.not.match(result.stderr, /✔/)
})

test('push encrypts a dotenv file, with --only and --except', async () => {
  const dir = tmpProject({
    'package.json': {},
    '.env.production': 'STRIPE_SECRET_KEY=sk_live_abc\nSTRIPE_PUBLIC=pk_live\nDB_URL="postgres://u:p@h/db"\nNODE_ENV=production\nEMPTY=\n'
  })
  await cli(['init'], { cwd: dir })
  const all = await cli(['push', '.env.production', '--to', 'netlify', '--except', 'NODE_ENV,*_PUBLIC'], { cwd: dir })
  assert.is(all.code, 0)
  assert.equal(all.exec.calls.map((call) => call.args[1]), ['STRIPE_SECRET_KEY', 'DB_URL'])
  assert.is(decrypt(all.exec.calls[1].args[2], keysOf(dir)), 'postgres://u:p@h/db')
  assert.match(all.stderr, /Skipped \(empty\): EMPTY/)

  const only = await cli(['push', '.env.production', '--to', 'netlify', '--only', 'STRIPE_*'], { cwd: dir })
  assert.equal(only.exec.calls.map((call) => call.args[1]), ['STRIPE_SECRET_KEY', 'STRIPE_PUBLIC'])
})

test('push does not double-encrypt values that are already sealed', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const sealed = encrypt('once', keysOf(dir))
  fs.writeFileSync(path.join(dir, '.env'), `A=${sealed}\n`)
  const result = await cli(['push', '.env', '--to', 'netlify'], { cwd: dir })
  assert.is(result.exec.calls[0].args[2], sealed)
})

test('push needs a file, a target and at least one value', async () => {
  const dir = tmpProject({ 'package.json': {}, '.env': 'A=1\n', '.env.empty': '# nothing\n' })
  await cli(['init'], { cwd: dir })
  assert.match((await cli(['push', '.env'], { cwd: dir })).stderr, /push needs a target/)
  assert.match((await cli(['push', 'missing.env', '--to', 'netlify'], { cwd: dir })).stderr, /cannot read missing.env/)
  assert.match((await cli(['push', '.env.empty', '--to', 'netlify'], { cwd: dir })).stderr, /no values to push/)
  assert.match((await cli(['push', '--to', 'netlify'], { cwd: dir })).stderr, /push needs one dotenv file/)
})

test('encrypt and decrypt round trip through stdin, never auto-decrypting plaintext', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const sealed = (await cli(['encrypt'], { cwd: dir, stdin: 'round trip\n' })).stdout.trim()
  assert.ok(isEncrypted(sealed))
  assert.is((await cli(['decrypt'], { cwd: dir, stdin: `${sealed}\n` })).stdout, 'round trip\n')
  assert.is((await cli(['decrypt', sealed], { cwd: dir })).stdout, 'round trip\n')
  const plain = await cli(['decrypt', 'not-encrypted'], { cwd: dir })
  assert.is(plain.code, 1)
  assert.match(plain.stderr, /not encrypted/)
})

test('decrypt, check and rotate need an existing key', async () => {
  const dir = tmpProject({ 'package.json': {} })
  for (const argv of [['decrypt', 'enc:v1:AAAA'], ['check', 'A', '--to', 'netlify'], ['rotate']]) {
    const result = await cli(argv, { cwd: dir })
    assert.is(result.code, 1)
    assert.match(result.stderr, /no key file found/)
  }
  assert.is(findKeyFile(dir), null)
})

test('PRESEAL_KEY stands in when there is no key file', async () => {
  const dir = tmpProject({ 'package.json': {} })
  const key = (await cli(['keygen'])).stdout.trim()
  const result = await cli(['encrypt'], { cwd: dir, stdin: 'x', env: { PRESEAL_KEY: key } })
  assert.is(decrypt(result.stdout.trim(), key), 'x')
  assert.is(findKeyFile(dir), null)
})

test('check reports ok, plaintext, missing and undecryptable values', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const keys = keysOf(dir)
  const other = (await cli(['keygen'])).stdout.trim()
  const store = { GOOD: encrypt('g', keys), PLAIN: 'sk_live_plain', FOREIGN: encrypt('f', other) }
  const exec = fakeExec((cmd, args) => JSON.stringify({ [args[1]]: store[args[1]] }))

  const ok = await cli(['check', 'GOOD', '--to', 'netlify'], { cwd: dir, exec })
  assert.is(ok.code, 0)
  assert.match(ok.stderr, /✔ GOOD in Netlify \(linked site, context dev\): decrypts with key v1/)

  const bad = await cli(['check', 'GOOD', 'PLAIN', 'MISSING', 'FOREIGN', '--to', 'netlify'], { cwd: dir, exec })
  assert.is(bad.code, 1)
  assert.match(bad.stderr, /✖ PLAIN .*: is stored as plaintext/)
  assert.match(bad.stderr, /✖ MISSING .*: is not set/)
  assert.match(bad.stderr, /✖ FOREIGN .*: could not decrypt/)
  assert.not.match(bad.stderr, 'sk_live_plain')
})

test('reseal encrypts a plaintext value in place', async () => {
  const dir = tmpProject({ 'package.json': {}, '.env.production': 'STRIPE_SECRET_KEY=sk_live_plain\n' })
  await cli(['init'], { cwd: dir })
  const result = await cli(['reseal', 'STRIPE_SECRET_KEY', '--to', 'dotenv:.env.production'], { cwd: dir })
  assert.is(result.code, 0)
  assert.match(result.stderr, /plaintext → v1/)
  const stored = parseDotenv(fs.readFileSync(path.join(dir, '.env.production'), 'utf8')).STRIPE_SECRET_KEY
  assert.is(decrypt(stored, keysOf(dir)), 'sk_live_plain')
  assert.not.match(result.stderr + result.stdout, 'sk_live_plain')
})

test('rotate then reseal moves stored values to the new key', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  await cli(['set', 'A', '--to', 'dotenv:.env.sealed'], { cwd: dir, stdin: 'alpha' })
  const read = () => parseDotenv(fs.readFileSync(path.join(dir, '.env.sealed'), 'utf8')).A
  assert.ok(read().startsWith('enc:v1:'))

  const rotated = await cli(['rotate'], { cwd: dir })
  assert.match(rotated.stderr, /Added key v2 to env-key.js/)
  assert.equal(Object.keys(keysOf(dir)), ['v1', 'v2'])

  const dry = await cli(['reseal', 'A', '--to', 'dotenv:.env.sealed', '--dry-run'], { cwd: dir })
  assert.match(dry.stderr, /would write A .*: v1 → v2/)
  assert.ok(read().startsWith('enc:v1:'))

  await cli(['reseal', 'A', '--to', 'dotenv:.env.sealed'], { cwd: dir })
  assert.ok(read().startsWith('enc:v2:'))
  assert.is(decrypt(read(), keysOf(dir)), 'alpha')

  const before = read()
  const noop = await cli(['reseal', 'A', '--to', 'dotenv:.env.sealed'], { cwd: dir })
  assert.match(noop.stderr, /already encrypted with v2/)
  assert.is(read(), before)

  assert.match((await cli(['set', 'B'], { cwd: dir, stdin: 'beta' })).stdout, /^B=enc:v2:/)
})

test('rotate lists the old keys in plain English', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })

  const first = (await cli(['rotate'], { cwd: dir })).stderr
  assert.match(first, 'v1 still decrypts.')
  assert.match(first, 'Delete the v1 line from env-key.js')

  const second = (await cli(['rotate'], { cwd: dir })).stderr
  assert.match(second, 'v1 and v2 still decrypt.')
  assert.match(second, 'Delete the v1 and v2 lines from env-key.js')

  const third = (await cli(['rotate'], { cwd: dir })).stderr
  assert.match(third, 'v1, v2 and v3 still decrypt.')
  assert.match(third, 'Delete the v1, v2 and v3 lines from env-key.js')
})

test('check and reseal reject an invalid name before calling anything', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  for (const command of ['check', 'reseal']) {
    const result = await cli([command, 'GOOD', 'VAR_01 VAR_02', '--to', 'netlify'], { cwd: dir })
    assert.is(result.code, 1)
    assert.is(result.stderr, 'preseal: "VAR_01 VAR_02" is not a valid variable name\n')
    assert.is(result.exec.calls.length, 0)
  }
})

test('check and reseal say which Netlify context they read', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const missing = await cli(['check', 'PROD_ONLY', '--to', 'netlify'], { cwd: dir, exec: fakeExec(() => '{}') })
  assert.is(missing.stderr, '✖ PROD_ONLY in Netlify (linked site, context dev): is not set\n')
  const prod = await cli(['check', 'PROD_ONLY', '--to', 'netlify', '--context', 'production,deploy-preview'], { cwd: dir, exec: fakeExec(() => '{}') })
  assert.is(prod.stderr, '✖ PROD_ONLY in Netlify (linked site, context production): is not set\n')
  const reseal = await cli(['reseal', 'PROD_ONLY', '--to', 'netlify'], { cwd: dir, exec: fakeExec(() => '{}') })
  assert.is(reseal.stderr, 'preseal: PROD_ONLY is not set in Netlify (linked site, context dev)\n')
})

test('reseal and check refuse targets that cannot be read', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const result = await cli(['reseal', 'A', '--to', 'stdout'], { cwd: dir })
  assert.is(result.code, 1)
  assert.match(result.stderr, /cannot be read back/)
})

test('the real binary: init, set through a fake aws on PATH, then decrypt at runtime', () => {
  const dir = tmpProject({ 'package.json': {} })
  const binDir = path.join(dir, 'fakebin')
  fs.mkdirSync(binDir)
  const log = path.join(dir, 'aws-calls.jsonl')
  fs.writeFileSync(path.join(binDir, 'aws'), `#!/usr/bin/env node\nrequire('fs').appendFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2)) + '\\n')\n`, { mode: 0o755 })
  const env = Object.assign({}, process.env, { PATH: `${binDir}${path.delimiter}${process.env.PATH}` })
  delete env.PRESEAL_KEY

  execFileSync(process.execPath, [BIN, 'init'], { cwd: dir, env, stdio: 'pipe' })
  const set = spawnSync(process.execPath, [BIN, 'set', 'STRIPE_SECRET_KEY', '--to', 'ssm:/my-app/prod', '--region', 'us-west-2'], {
    cwd: dir, env, input: 'sk_live_real_binary\n'
  })
  assert.is(set.status, 0, set.stderr.toString())
  assert.match(set.stderr.toString(), /✔ STRIPE_SECRET_KEY → AWS SSM \(\/my-app\/prod\/<NAME>, us-west-2, SecureString\)/)

  const args = JSON.parse(fs.readFileSync(log, 'utf8').trim())
  assert.equal(args.slice(0, 4), ['ssm', 'put-parameter', '--name', '/my-app/prod/STRIPE_SECRET_KEY'])
  const ciphertext = args[5]
  assert.ok(isEncrypted(ciphertext))

  const runtime = execFileSync(process.execPath, ['-e', "process.stdout.write(require('./env-key').env('STRIPE_SECRET_KEY'))"], {
    cwd: dir,
    env: Object.assign({}, env, { STRIPE_SECRET_KEY: ciphertext })
  })
  assert.is(runtime.toString(), 'sk_live_real_binary')
})

test('the real binary: a missing tool says how to install it', () => {
  const dir = tmpProject({ 'package.json': {} })
  const emptyBin = path.join(dir, 'emptybin')
  fs.mkdirSync(emptyBin)
  const result = spawnSync(process.execPath, [BIN, 'set', 'A', '--to', 'netlify'], {
    cwd: dir, env: { PATH: emptyBin, HOME: dir }, input: 'alpha'
  })
  assert.is(result.status, 1)
  assert.match(result.stderr.toString(), /`netlify` was not found on your PATH. Install the Netlify CLI/)
})

/** Every file under a directory with its content, to prove a command wrote nothing. */
function snapshot(dir) {
  const files = {}
  const walk = (sub) => {
    for (const entry of fs.readdirSync(path.join(dir, sub), { withFileTypes: true })) {
      const name = path.join(sub, entry.name)
      if (entry.isDirectory()) walk(name)
      else files[name] = fs.readFileSync(path.join(dir, name), 'utf8')
    }
  }
  walk('')
  return files
}

test('a dry run in a project with no key file writes nothing and names the file it would create', async () => {
  const dir = tmpProject({ 'package.json': {}, '.env': 'A=alpha\nB=beta\n' })
  const before = snapshot(dir)
  const runs = [
    ['set', 'A', '--to', 'netlify', '--dry-run'],
    ['set', 'A', '--dry-run'],
    ['push', '.env', '--to', 'ssm:/app', '--dry-run'],
    ['reseal', 'A', '--to', 'dotenv:.env', '--dry-run'],
    ['init', '--dry-run'],
    // A custom location is normally recorded in package.json.
    ['init', '--file', 'config/key.mjs', '--dry-run']
  ]
  for (const argv of runs) {
    const result = await cli(argv, { cwd: dir, stdin: 'alpha' })
    const file = argv.includes('--file') ? 'config/key.mjs' : 'env-key.js'
    assert.is(result.code, 0, `${argv.join(' ')}: ${result.stderr}`)
    assert.ok(result.stderr.startsWith(`would create ${file} with a new key (v1)\n`), `${argv.join(' ')}: ${result.stderr}`)
    assert.not.match(result.stderr, /Created|Commit /)
    assert.is(result.stdout, '', argv.join(' '))
    assert.is(result.exec.calls.length, 0)
    assert.equal(snapshot(dir), before, argv.join(' '))
  }
  const set = await cli(runs[0], { cwd: dir, stdin: 'alpha' })
  assert.match(set.stderr, /would write A → Netlify \(linked site, all contexts\) {2}\(key v1\)/)
  const reseal = await cli(runs[3], { cwd: dir })
  assert.match(reseal.stderr, /would write A in .*: plaintext → v1/)

  // `encrypt` prints ciphertext, which is no use without the key that made it.
  const encrypt = await cli(['encrypt', 'alpha', '--dry-run'], { cwd: dir })
  assert.is(encrypt.code, 1)
  assert.is(encrypt.stdout, '')
  assert.match(encrypt.stderr, /no key file found/)
  assert.equal(snapshot(dir), before)
})

test('a dry run with a key file uses it and still writes nothing', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const before = snapshot(dir)

  const set = await cli(['set', 'A', '--to', 'netlify', '--dry-run'], { cwd: dir, stdin: 'alpha' })
  assert.not.match(set.stderr, /would create/)

  const rotate = await cli(['rotate', '--dry-run'], { cwd: dir })
  assert.is(rotate.code, 0)
  assert.is(rotate.stderr, 'would add key v2 to env-key.js\n')

  const again = await cli(['init', '--dry-run'], { cwd: dir })
  assert.is(again.code, 1)
  assert.match(again.stderr, /already exists/)

  assert.equal(snapshot(dir), before)
  assert.equal(Object.keys(keysOf(dir)), ['v1'])
})

test('--cwd is where the netlify, aws and op CLIs run', async () => {
  const root = tmpProject({ 'apps/api/package.json': {} })
  const api = path.join(root, 'apps/api')
  const exec = fakeExec((cmd) => (cmd === 'op-stash' ? 'sk_live_abc\n' : ''))
  const result = await cli(
    ['set', 'A', '--from', 'op://Eng/Stripe/secret', '--to', 'netlify', '--to', 'ssm:/app', '--to', 'op://Eng/my-app', '--cwd', 'apps/api'],
    { cwd: root, exec }
  )
  assert.is(result.code, 0, result.stderr)
  assert.ok(fs.existsSync(path.join(api, 'env-key.js')))
  assert.equal([...new Set(exec.calls.map((call) => call.cmd))].sort(), ['aws', 'netlify', 'op', 'op-stash'])
  for (const call of exec.calls) assert.is(call.opts.cwd, api, call.cmd)

  const ssm = await cli(['set', 'B', '--from', 'ssm:/shared/b', '--cwd', 'apps/api'], { cwd: root, exec: fakeExec(() => 'beta\n') })
  assert.is(ssm.exec.calls[0].opts.cwd, api)
})

test('--cwd must be a directory that exists', async () => {
  const root = tmpProject({ 'package.json': {}, 'a-file': '' })
  for (const dir of ['apps/typo', 'a-file']) {
    for (const argv of [['init'], ['set', 'A', '--to', 'netlify'], ['check', 'A', '--to', 'netlify']]) {
      const result = await cli([...argv, '--cwd', dir], { cwd: root, stdin: 'alpha' })
      assert.is(result.code, 1)
      assert.is(result.stderr, `preseal: --cwd ${dir} is not a directory\n`)
      assert.is(result.exec.calls.length, 0)
    }
  }
  assert.not.ok(fs.existsSync(path.join(root, 'apps')))
})

test('the real binary: --cwd changes the directory a tool runs in', () => {
  const root = tmpProject({ 'apps/api/package.json': {} })
  const api = path.join(root, 'apps/api')
  const binDir = path.join(root, 'fakebin')
  fs.mkdirSync(binDir)
  const log = path.join(root, 'netlify-cwd.txt')
  fs.writeFileSync(path.join(binDir, 'netlify'), `#!/usr/bin/env node\nrequire('fs').appendFileSync(${JSON.stringify(log)}, process.cwd() + '\\n')\n`, { mode: 0o755 })
  const env = Object.assign({}, process.env, { PATH: `${binDir}${path.delimiter}${process.env.PATH}` })
  delete env.PRESEAL_KEY

  const inApi = spawnSync(process.execPath, [BIN, 'set', 'A', '--to', 'netlify', '--cwd', 'apps/api'], { cwd: root, env, input: 'alpha' })
  assert.is(inApi.status, 0, inApi.stderr.toString())
  const here = spawnSync(process.execPath, [BIN, 'set', 'A', '--to', 'netlify', '--key-file', 'apps/api/env-key.js'], { cwd: root, env, input: 'alpha' })
  assert.is(here.status, 0, here.stderr.toString())

  const dirs = fs.readFileSync(log, 'utf8').trim().split('\n').map((dir) => fs.realpathSync(dir))
  assert.equal(dirs, [fs.realpathSync(api), fs.realpathSync(root)])
})

test('exec: a working directory that is missing is not reported as a missing tool', async () => {
  const { exec } = require('../src/exec')
  let message = ''
  try {
    await exec(process.execPath, ['--version'], { cwd: path.join(tmpProject(), 'gone') })
  } catch (error) {
    message = error.message
  }
  assert.match(message, /^preseal: cannot run `.*` in .*gone: no such directory$/)
  assert.not.match(message, /PATH/)
})

test.run()
