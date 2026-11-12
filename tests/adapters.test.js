const { test } = require('uvu')
const assert = require('uvu/assert')
const fs = require('fs')
const path = require('path')
const {
  resolveTarget,
  createNetlifyAdapter,
  createSsmAdapter,
  createOnePasswordAdapter,
  readOpRef
} = require('../src/adapters')
const { readSource, isSourceSpec } = require('../src/sources')
const { seal } = require('../src/seal')
const { decrypt, generateKey, encrypt } = require('../src/crypto')
const { tmpProject, fakeExec } = require('./helpers')

const VALUE = 'enc:v1:AAAA+/bbbb=='

test('netlify: set passes name and value first, then flags', async () => {
  const exec = fakeExec()
  const adapter = createNetlifyAdapter({ site: 'my-site', context: ['production', 'deploy-preview'], scope: ['functions'], secret: true }, { exec })
  await adapter.set('STRIPE_SECRET_KEY', VALUE)
  assert.equal(exec.calls[0].cmd, 'netlify')
  assert.equal(exec.calls[0].args, [
    'env:set', 'STRIPE_SECRET_KEY', VALUE, '--force',
    '--context', 'production', 'deploy-preview',
    '--scope', 'functions',
    '--secret',
    '--site', 'my-site'
  ])
  assert.is(adapter.label, 'Netlify (site my-site, context production, deploy-preview, scope functions, secret)')
  assert.is(adapter.readLabel, 'Netlify (site my-site, context production, scope functions)')
})

test('netlify: the linked site needs no flags', async () => {
  const exec = fakeExec()
  const adapter = createNetlifyAdapter({}, { exec })
  await adapter.set('A', VALUE)
  assert.equal(exec.calls[0].args, ['env:set', 'A', VALUE, '--force'])
  assert.is(adapter.label, 'Netlify (linked site, all contexts)')
  assert.is(adapter.readLabel, 'Netlify (linked site, context dev)')
})

test('netlify: get reads the --json output, or plain text', async () => {
  const json = createNetlifyAdapter({ context: ['production'] }, { exec: fakeExec(() => JSON.stringify({ A: VALUE })) })
  assert.is(await json.get('A'), VALUE)
  const exec = fakeExec(() => `${VALUE}\n`)
  const text = createNetlifyAdapter({ context: ['production'], site: 's' }, { exec })
  assert.is(await text.get('A'), VALUE)
  assert.equal(exec.calls[0].args, ['env:get', 'A', '--json', '--context', 'production', '--site', 's'])
  const empty = createNetlifyAdapter({}, { exec: fakeExec(() => '{}') })
  assert.is(await empty.get('A'), undefined)
})

test('netlify: an unlinked folder is an error, though the CLI exits 0', async () => {
  const exec = fakeExec(() => 'No project id found, please run inside a project folder or `netlify link`\n')
  const adapter = createNetlifyAdapter({}, { exec })
  for (const action of [() => adapter.set('A', VALUE), () => adapter.get('A')]) {
    let message = ''
    try { await action() } catch (err) { message = err.message }
    assert.match(message, /no Netlify site is linked/)
  }
})

test('netlify: secrets need a non-dev context', () => {
  assert.throws(() => createNetlifyAdapter({ secret: true }), /non-dev --context/)
  assert.throws(() => createNetlifyAdapter({ secret: true, context: ['dev'] }), /non-dev --context/)
  assert.is(createNetlifyAdapter({ secret: true, context: ['production'] }).name, 'netlify')
})

test('netlify: a masked secret is an error, never a value to reseal', async () => {
  const exec = fakeExec(() => JSON.stringify({ STRIPE_SECRET_KEY: '****************5Q==' }))
  const adapter = createNetlifyAdapter({ context: ['production'] }, { exec })
  let message = ''
  try {
    await adapter.get('STRIPE_SECRET_KEY')
  } catch (err) {
    message = err.message
  }
  assert.match(message, /STRIPE_SECRET_KEY is a Netlify secret/)
})

test('ssm: set writes a SecureString under the path prefix', async () => {
  const exec = fakeExec()
  const adapter = createSsmAdapter({ path: '/my-app/prod/', region: 'us-west-2', profile: 'gtm-test' }, { exec })
  await adapter.set('STRIPE_SECRET_KEY', VALUE)
  assert.equal(exec.calls[0].cmd, 'aws')
  assert.equal(exec.calls[0].args, [
    'ssm', 'put-parameter', '--name', '/my-app/prod/STRIPE_SECRET_KEY', '--value', VALUE,
    '--type', 'SecureString', '--overwrite', '--region', 'us-west-2', '--profile', 'gtm-test'
  ])
})

test('ssm: {name} templates, String type, kms key and tier', async () => {
  const exec = fakeExec()
  const templated = createSsmAdapter({ path: '/app/{name}/prod', type: 'String', kmsKeyId: 'alias/x', tier: 'Advanced' }, { exec })
  await templated.set('DB_URL', VALUE)
  assert.equal(exec.calls[0].args, [
    'ssm', 'put-parameter', '--name', '/app/DB_URL/prod', '--value', VALUE, '--type', 'String', '--overwrite', '--tier', 'Advanced'
  ])
  const secure = createSsmAdapter({ path: '/app', kmsKeyId: 'alias/x' }, { exec })
  await secure.set('DB_URL', VALUE)
  assert.equal(exec.calls[1].args.slice(-2), ['--key-id', 'alias/x'])
})

test('ssm: get decrypts and strips the trailing newline', async () => {
  const exec = fakeExec(() => `${VALUE}\n`)
  const adapter = createSsmAdapter({ path: '/app' }, { exec })
  assert.is(await adapter.get('A'), VALUE)
  assert.equal(exec.calls[0].args, [
    'ssm', 'get-parameter', '--name', '/app/A', '--with-decryption', '--query', 'Parameter.Value', '--output', 'text'
  ])
})

test('ssm: get returns undefined for a missing parameter, and still throws other errors', async () => {
  const notFound = 'aws: [ERROR]: An error occurred (ParameterNotFound) when calling the GetParameter operation:'
  const missing = createSsmAdapter({ path: '/app' }, { exec: fakeExec(() => ({ code: 254, stderr: notFound })) })
  assert.is(await missing.get('A'), undefined)

  const denied = createSsmAdapter({ path: '/app' }, { exec: fakeExec(() => ({ code: 254, stderr: 'AccessDeniedException' })) })
  let message = ''
  try {
    await denied.get('A')
  } catch (err) {
    message = err.message
  }
  assert.match(message, /AccessDeniedException/)
})

test('ssm: a relative path is rejected', () => {
  assert.throws(() => createSsmAdapter({ path: 'my-app' }), /absolute path/)
})

test('1password: edits the item when it exists', async () => {
  const exec = fakeExec()
  const adapter = createOnePasswordAdapter({ vault: 'Engineering', item: 'my-app' }, { exec })
  await adapter.set('STRIPE_SECRET_KEY', VALUE)
  assert.is(exec.calls.length, 1)
  assert.equal(exec.calls[0].args, ['item', 'edit', 'my-app', '--vault', 'Engineering', `STRIPE_SECRET_KEY[concealed]=${VALUE}`])
})

test('1password: creates the item when it does not exist', async () => {
  const exec = fakeExec((cmd, args) => (args[1] === 'edit'
    ? { code: 1, stderr: '[ERROR] "my-app" isn\'t an item in the "Engineering" vault.' }
    : ''))
  const adapter = createOnePasswordAdapter({ vault: 'Engineering', item: 'my-app', section: 'prod.env' }, { exec })
  await adapter.set('DB.URL', VALUE)
  assert.is(exec.calls.length, 2)
  assert.equal(exec.calls[1].args, [
    'item', 'create', '--category', 'Secure Note', '--title', 'my-app', '--vault', 'Engineering',
    `prod\\.env.DB\\.URL[concealed]=${VALUE}`
  ])
})

test('1password: other edit failures surface, without creating anything', async () => {
  const exec = fakeExec(() => ({ code: 1, stderr: '[ERROR] authorization prompt dismissed' }))
  const adapter = createOnePasswordAdapter({ vault: 'V', item: 'I' }, { exec })
  let message = ''
  try {
    await adapter.set('A', VALUE)
  } catch (err) {
    message = err.message
  }
  assert.match(message, /authorization prompt dismissed/)
  assert.is(exec.calls.length, 1)
})

test('1password: reads prefer op-stash and fall back to op', async () => {
  const stash = fakeExec(() => 'from-stash\n')
  assert.is(await readOpRef('op://V/I/f', stash), 'from-stash')
  assert.equal(stash.calls.map((call) => call.cmd), ['op-stash'])

  const plain = fakeExec(() => 'from-op\n', { missing: ['op-stash'] })
  assert.is(await readOpRef('op://V/I/f', plain), 'from-op')
  assert.equal(plain.calls.map((call) => [call.cmd, call.args]), [['op-stash', ['read', 'op://V/I/f']], ['op', ['read', 'op://V/I/f']]])

})

test('1password: the target reads with plain `op read`, so a cached value never hides a write', async () => {
  const exec = fakeExec(() => `${VALUE}\n`)
  const adapter = createOnePasswordAdapter({ vault: 'V', item: 'I', section: 'S' }, { exec })
  assert.is(await adapter.get('A'), VALUE)
  assert.equal(exec.calls.map((call) => [call.cmd, call.args]), [['op', ['read', 'op://V/I/S/A']]])
})

test('1password: get returns undefined for a missing field or item, and still throws other errors', async () => {
  const errors = [
    "[ERROR] could not read secret 'op://V/I/A': item 'V/I' does not have a field 'A'",
    '[ERROR] could not read secret \'op://V/I/A\': could not get item V/I: "I" isn\'t an item in the "V" vault.'
  ]
  for (const stderr of errors) {
    const adapter = createOnePasswordAdapter({ vault: 'V', item: 'I' }, { exec: fakeExec(() => ({ code: 1, stderr })) })
    assert.is(await adapter.get('A'), undefined)
  }

  const denied = createOnePasswordAdapter({ vault: 'V', item: 'I' }, { exec: fakeExec(() => ({ code: 1, stderr: '[ERROR] authorization prompt dismissed' })) })
  let message = ''
  try {
    await denied.get('A')
  } catch (err) {
    message = err.message
  }
  assert.match(message, /authorization prompt dismissed/)
})

test('dotenv: set and get against a file', async () => {
  const dir = tmpProject({ '.env.production': 'KEEP=1\n' })
  const adapter = resolveTarget('dotenv:.env.production', { cwd: dir })
  await adapter.set('A', VALUE)
  assert.is(fs.readFileSync(path.join(dir, '.env.production'), 'utf8'), `KEEP=1\nA=${VALUE}\n`)
  assert.is(await adapter.get('A'), VALUE)
  assert.is(await adapter.get('NOPE'), undefined)
})

test('resolveTarget maps specs to adapters', async () => {
  const exec = fakeExec()
  assert.is(resolveTarget('netlify', {}, { exec }).name, 'netlify')
  await resolveTarget('netlify:other-site', { site: 'ignored' }, { exec }).set('A', VALUE)
  assert.equal(exec.calls[0].args.slice(-2), ['--site', 'other-site'])
  await resolveTarget('netlify', { site: 'from-flag' }, { exec }).set('A', VALUE)
  assert.equal(exec.calls[1].args.slice(-2), ['--site', 'from-flag'])
  assert.is(resolveTarget('ssm:/a/b', {}, { exec }).name, 'ssm')
  assert.is(resolveTarget('op://V/I', {}, { exec }).name, '1password')
  assert.is(resolveTarget('op://V/I/Section', {}, { exec }).label, '1Password (op://V/I/Section/<NAME>)')
  assert.is(resolveTarget('stdout').name, 'stdout')
  const custom = { name: 'vault', set: async () => {} }
  assert.is(resolveTarget(custom), custom)
})

test('resolveTarget rejects specs it does not know', () => {
  assert.throws(() => resolveTarget('vercel'), /unknown target "vercel"/)
  assert.throws(() => resolveTarget('op://OnlyVault'), /op:\/\/Vault\/Item/)
  assert.throws(() => resolveTarget('op://V/I/S/extra'), /op:\/\/Vault\/Item/)
  assert.throws(() => resolveTarget({ name: 'x' }), /set\(name, value\)/)
  assert.throws(() => resolveTarget(''), /empty target/)
})

test('sources: op, ssm, env and file', async () => {
  assert.ok(isSourceSpec('op://V/I/f'))
  assert.ok(isSourceSpec('ssm:/a/b'))
  assert.ok(isSourceSpec('env:HOME'))
  assert.ok(isSourceSpec('file:./x'))
  assert.not.ok(isSourceSpec('postgres://u:p@h/db'))
  assert.not.ok(isSourceSpec('sk_live_abc'))

  const exec = fakeExec((cmd) => (cmd === 'aws' ? 'from-ssm\n' : 'from-op\n'))
  assert.is(await readSource('op://V/I/f', { exec }), 'from-op')
  assert.is(await readSource('ssm:/a/b', { exec, region: 'eu-west-1' }), 'from-ssm')
  assert.equal(exec.calls[1].args, [
    'ssm', 'get-parameter', '--name', '/a/b', '--with-decryption', '--query', 'Parameter.Value', '--output', 'text', '--region', 'eu-west-1'
  ])
  assert.is(await readSource('env:X', { env: { X: 'from-env' } }), 'from-env')
  let message = ''
  try { await readSource('env:NOPE', { env: {} }) } catch (err) { message = err.message }
  assert.match(message, /NOPE is not set/)
  const dir = tmpProject({ 'secret.txt': 'from-file\n' })
  assert.is(await readSource('file:secret.txt', { cwd: dir }), 'from-file')
})

test('seal encrypts once and writes the same ciphertext to every target', async () => {
  const keys = { v1: generateKey() }
  const exec = fakeExec()
  const events = []
  const result = await seal({
    values: { A: 'alpha', B: 'beta' },
    keys,
    targets: ['netlify', 'ssm:/app/prod'],
    exec,
    onWrite: (event) => events.push(`${event.target}:${event.name}:${event.version}`)
  })
  assert.equal(events, ['netlify:A:v1', 'netlify:B:v1', 'ssm:A:v1', 'ssm:B:v1'])
  assert.is(decrypt(result.sealed.A, keys), 'alpha')
  assert.is(exec.calls[0].args[2], result.sealed.A)
  assert.is(exec.calls[2].args[5], result.sealed.A)
  assert.not.match(JSON.stringify(exec.calls), 'alpha')
})

test('seal passes already-encrypted values through and honors dryRun', async () => {
  const keys = { v1: generateKey() }
  const already = encrypt('x', keys)
  const exec = fakeExec()
  const result = await seal({ values: { A: already }, keys, targets: ['netlify'], exec, dryRun: true })
  assert.is(result.sealed.A, already)
  assert.is(exec.calls.length, 0)
  assert.is(result.written.length, 1)
})

test('seal rejects empty values before writing anything', async () => {
  const exec = fakeExec()
  let message = ''
  try {
    await seal({ values: { A: 'ok', B: '' }, keys: generateKey(), targets: ['netlify'], exec })
  } catch (err) {
    message = err.message
  }
  assert.match(message, /B has no value/)
  assert.is(exec.calls.length, 0)
})

test('a target or source given a cwd runs its CLI there', async () => {
  const dir = tmpProject()
  for (const spec of ['netlify', 'ssm:/app', 'op://Vault/Item']) {
    const exec = fakeExec()
    await resolveTarget(spec, { cwd: dir }, { exec }).set('A', VALUE)
    assert.ok(exec.calls.length, spec)
    for (const call of exec.calls) assert.is(call.opts.cwd, dir, spec)

    const plain = fakeExec()
    await resolveTarget(spec, {}, { exec: plain }).set('A', VALUE)
    for (const call of plain.calls) assert.is(call.opts.cwd, undefined, spec)
  }

  const exec = fakeExec(() => 'value\n')
  await readSource('ssm:/a/b', { exec, cwd: dir })
  await readSource('op://Vault/Item/field', { exec, cwd: dir })
  assert.is(exec.calls.length, 2)
  for (const call of exec.calls) assert.is(call.opts.cwd, dir)
})

test.run()
