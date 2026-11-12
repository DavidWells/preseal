const { test } = require('uvu')
const assert = require('uvu/assert')
const { readMany, writeMany } = require('../src/batch')
const { createNetlifyAdapter, createSsmAdapter, createOnePasswordAdapter } = require('../src/adapters')
const { seal } = require('../src/seal')
const { run } = require('../src/cli')
const { encrypt, decrypt, versionOf } = require('../src/crypto')
const { readKeyFile, findKeyFile } = require('../src/key-file')
const { tmpProject, fakeExec } = require('./helpers')

const A = 'enc:v1:AAAA+/aaaa=='
const B = 'enc:v1:BBBB+/bbbb=='
const calls = (exec) => exec.calls.map((call) => `${call.cmd} ${call.args.join(' ')}`)
const tick = () => new Promise((resolve) => setImmediate(resolve))

async function cli(argv, opts = {}) {
  let stderr = ''
  let stdout = ''
  const exec = opts.exec || fakeExec()
  const code = await run(argv, {
    cwd: opts.cwd,
    env: {},
    exec,
    isTTY: false,
    readStdin: async () => opts.stdin || '',
    stdout: (text) => { stdout += text },
    stderr: (text) => { stderr += text }
  })
  return { code, stdout, stderr, exec }
}

test('readMany: one get per name without getMany, and errors stay with their name', async () => {
  const adapter = {
    name: 'x',
    async set() {},
    async get(name) {
      if (name === 'BAD') throw new Error('boom')
      return name === 'NOPE' ? undefined : `value-${name}`
    }
  }
  const results = await readMany(adapter, ['A', 'BAD', 'NOPE'])
  assert.is(results[0].value, 'value-A')
  assert.is(results[1].error.message, 'boom')
  assert.equal(results[2], { value: undefined })
})

test('readMany: a single name uses get, several use getMany', async () => {
  const seen = []
  const adapter = {
    name: 'x',
    async set() {},
    async get(name) { seen.push(`get ${name}`); return 'one' },
    async getMany(names) { seen.push(`getMany ${names.join(',')}`); return names.map(() => ({ value: 'many' })) }
  }
  assert.equal(await readMany(adapter, ['A']), [{ value: 'one' }])
  assert.equal(await readMany(adapter, ['A', 'B']), [{ value: 'many' }, { value: 'many' }])
  assert.equal(seen, ['get A', 'getMany A,B'])
})

test('writeMany: setMany takes all entries in one call and reports them in order', async () => {
  const batches = []
  const adapter = { name: 'x', async set() { throw new Error('not used') }, async setMany(entries) { batches.push(entries) } }
  const reported = []
  await writeMany(adapter, [['A', '1'], ['B', '2']], (index) => reported.push(index))
  assert.equal(batches, [[['A', '1'], ['B', '2']]])
  assert.equal(reported, [0, 1])
})

test('writeMany: without concurrency, writes go one after another', async () => {
  let running = 0
  let peak = 0
  const adapter = { name: 'x', async set() { peak = Math.max(peak, ++running); await tick(); running-- } }
  const reported = []
  await writeMany(adapter, [['A', '1'], ['B', '2'], ['C', '3']], (index) => reported.push(index))
  assert.is(peak, 1)
  assert.equal(reported, [0, 1, 2])
})

test('writeMany: with concurrency, the first write goes alone and the rest overlap, reported in order', async () => {
  let running = 0
  let peak = 0
  const started = []
  const adapter = {
    name: 'x',
    concurrency: 3,
    async set(name) {
      started.push(`${name}@${running}`)
      peak = Math.max(peak, ++running)
      // later names finish first, to prove the report order is by position
      for (let i = 0; i < 10 - Number(name); i++) await tick()
      running--
    }
  }
  const entries = Array.from({ length: 8 }, (_, i) => [String(i), 'v'])
  const reported = []
  await writeMany(adapter, entries, (index) => reported.push(index))
  assert.is(started[0], '0@0')
  assert.is(started[1], '1@0', 'the second write starts only after the first is done')
  assert.is(peak, 3)
  assert.equal(reported, [0, 1, 2, 3, 4, 5, 6, 7])
})

test('writeMany: a failing first write stops everything', async () => {
  const seen = []
  const adapter = { name: 'x', concurrency: 4, async set(name) { seen.push(name); throw new Error('not linked') } }
  const reported = []
  let message = ''
  try {
    await writeMany(adapter, [['A', '1'], ['B', '2'], ['C', '3']], (index) => reported.push(index))
  } catch (err) {
    message = err.message
  }
  assert.is(message, 'not linked')
  assert.equal(seen, ['A'])
  assert.equal(reported, [])
})

test('writeMany: a later failure reports the entries before it and starts no new writes', async () => {
  const seen = []
  const adapter = {
    name: 'x',
    concurrency: 2,
    async set(name) {
      seen.push(name)
      await tick()
      if (name === 'C') throw new Error('C failed')
    }
  }
  const reported = []
  let message = ''
  try {
    await writeMany(adapter, ['A', 'B', 'C', 'D', 'E', 'F', 'G'].map((name) => [name, 'v']), (index) => reported.push(index))
  } catch (err) {
    message = err.message
  }
  assert.is(message, 'C failed')
  assert.equal(reported, [0, 1])
  assert.ok(seen.length < 7, 'writes after the failure were not all started')
})

test('netlify: getMany is one env:list, with env:get only for names the list does not answer', async () => {
  const exec = fakeExec((cmd, args) => {
    if (args[0] === 'env:list') return JSON.stringify({ A, B, EMPTY: '', SECRET: '****************5Q==' })
    return args[1] === 'INTERNAL' ? JSON.stringify({ INTERNAL: 'from-get' }) : '{}'
  })
  const adapter = createNetlifyAdapter({ context: ['production'], site: 'my-site' }, { exec })
  const results = await adapter.getMany(['A', 'NOPE', 'B', 'EMPTY', 'INTERNAL', 'SECRET'])
  assert.equal(results.slice(0, 5), [{ value: A }, { value: undefined }, { value: B }, { value: undefined }, { value: 'from-get' }])
  assert.match(results[5].error.message, /SECRET is a Netlify secret/)
  assert.equal(calls(exec), [
    'netlify env:list --json --context production --site my-site',
    'netlify env:get NOPE --json --context production --site my-site',
    'netlify env:get EMPTY --json --context production --site my-site',
    'netlify env:get INTERNAL --json --context production --site my-site'
  ])
})

test('netlify: when env:list fails, every name reads exactly as get would', async () => {
  const unlinked = createNetlifyAdapter({}, { exec: fakeExec(() => 'No project id found, please run inside a project folder or `netlify link`') })
  const results = await unlinked.getMany(['A', 'B'])
  assert.match(results[0].error.message, /no Netlify site is linked/)
  assert.match(results[1].error.message, /no Netlify site is linked/)
})

test('ssm: getMany asks for ten names per call and maps values back by name', async () => {
  const names = Array.from({ length: 12 }, (_, i) => `VAR_${i}`)
  const exec = fakeExec((cmd, args) => {
    if (args[1] === 'get-parameter') return { code: 254, stderr: 'An error occurred (ParameterNotFound) when calling the GetParameter operation' }
    const asked = args.slice(args.indexOf('--names') + 1, args.indexOf('--with-decryption'))
    // the API answers in its own order and leaves missing names out
    const Parameters = asked.filter((name) => !name.endsWith('VAR_3')).reverse().map((Name) => ({ Name, Value: `value of ${Name}` }))
    return JSON.stringify({ Parameters, InvalidParameters: asked.filter((name) => name.endsWith('VAR_3')) })
  })
  const adapter = createSsmAdapter({ path: '/app/prod', region: 'us-east-1' }, { exec })
  const results = await adapter.getMany(names)
  assert.is(results[0].value, 'value of /app/prod/VAR_0')
  assert.is(results[11].value, 'value of /app/prod/VAR_11')
  assert.equal(results[3], { value: undefined })
  assert.equal(exec.calls.map((call) => call.args[1]), ['get-parameters', 'get-parameters', 'get-parameter'])
  assert.is(exec.calls[0].args.filter((arg) => arg.startsWith('/app/prod/')).length, 10)
  assert.equal(exec.calls[0].args.slice(-5), ['--with-decryption', '--output', 'json', '--region', 'us-east-1'])
})

test('ssm: a failed batch falls back to one get per name', async () => {
  const exec = fakeExec((cmd, args) => (args[1] === 'get-parameters' ? { code: 254, stderr: 'AccessDeniedException' } : 'from-get\n'))
  const adapter = createSsmAdapter({ path: '/app' }, { exec })
  assert.equal(await adapter.getMany(['A', 'B']), [{ value: 'from-get' }, { value: 'from-get' }])
  assert.equal(exec.calls.map((call) => call.args[1]), ['get-parameters', 'get-parameter', 'get-parameter'])
})

const item = (fields) => JSON.stringify({ id: 'x', title: 'my-app', fields: [{ id: 'notesPlain', type: 'STRING', label: 'notesPlain' }, ...fields] })

test('1password: getMany is one item get; anything ambiguous is left to op read', async () => {
  const exec = fakeExec((cmd, args) => {
    if (args[0] === 'read') return 'from-read\n'
    return item([
      { id: 'a', type: 'CONCEALED', label: 'A', value: A },
      { id: 'b', type: 'CONCEALED', label: 'B', value: B, section: { id: 's', label: 'prod' } },
      { id: 'd1', type: 'CONCEALED', label: 'DUP', value: 'one' },
      { id: 'd2', type: 'CONCEALED', label: 'DUP', value: 'two' },
      { id: 'o', type: 'OTP', label: 'TOTP', value: 'otpauth://x' },
      { id: 'e', type: 'CONCEALED', label: 'EMPTY' }
    ])
  })
  const adapter = createOnePasswordAdapter({ vault: 'V', item: 'my-app' }, { exec })
  const results = await adapter.getMany(['A', 'B', 'DUP', 'TOTP', 'EMPTY', 'NOPE'])
  assert.equal(results.map((result) => result.value), [A, 'from-read', 'from-read', 'from-read', 'from-read', 'from-read'])
  assert.equal(calls(exec), [
    'op item get my-app --vault V --format json',
    'op read op://V/my-app/B',
    'op read op://V/my-app/DUP',
    'op read op://V/my-app/TOTP',
    'op read op://V/my-app/EMPTY',
    'op read op://V/my-app/NOPE'
  ])

  const inSection = createOnePasswordAdapter({ vault: 'V', item: 'my-app', section: 'prod' }, { exec: fakeExec(() => item([{ id: 'b', type: 'CONCEALED', label: 'B', value: B, section: { id: 's', label: 'prod' } }, { id: 'c', type: 'CONCEALED', label: 'C', value: A, section: { id: 's', label: 'prod' } }])) })
  assert.equal(await inSection.getMany(['B', 'C']), [{ value: B }, { value: A }])
})

test('1password: a missing item means nothing is set, in one call', async () => {
  const exec = fakeExec(() => ({ code: 1, stderr: '[ERROR] "my-app" isn\'t an item in the "V" vault.' }))
  const adapter = createOnePasswordAdapter({ vault: 'V', item: 'my-app' }, { exec })
  assert.equal(await adapter.getMany(['A', 'B']), [{ value: undefined }, { value: undefined }])
  assert.is(exec.calls.length, 1)
})

test('1password: setMany writes every field in one edit, and creates the item when needed', async () => {
  const exec = fakeExec()
  const adapter = createOnePasswordAdapter({ vault: 'V', item: 'my-app', section: 'prod' }, { exec })
  await adapter.setMany([['A', A], ['B', B]])
  assert.equal(calls(exec), [`op item edit my-app --vault V prod.A[concealed]=${A} prod.B[concealed]=${B}`])

  const fresh = fakeExec((cmd, args) => (args[1] === 'edit' ? { code: 1, stderr: '"my-app" isn\'t an item in the "V" vault.' } : ''))
  await createOnePasswordAdapter({ vault: 'V', item: 'my-app' }, { exec: fresh }).setMany([['A', A], ['B', B]])
  assert.equal(calls(fresh)[1], `op item create --category Secure Note --title my-app --vault V A[concealed]=${A} B[concealed]=${B}`)
  assert.is(fresh.calls.length, 2)
})

test('1password: setMany splits a very large push into several edits', async () => {
  const exec = fakeExec()
  const adapter = createOnePasswordAdapter({ vault: 'V', item: 'I' }, { exec })
  await adapter.setMany(Array.from({ length: 120 }, (_, i) => [`VAR_${i}`, A]))
  assert.equal(exec.calls.map((call) => call.args.length - 5), [50, 50, 20])

  const big = fakeExec()
  await createOnePasswordAdapter({ vault: 'V', item: 'I' }, { exec: big }).setMany([['A', 'x'.repeat(40000)], ['B', 'x'.repeat(40000)], ['C', 'c']])
  assert.equal(big.calls.map((call) => call.args.length - 5), [1, 2])
})

test('seal: writes to a concurrent target are reported in the order given', async () => {
  const exec = fakeExec()
  const events = []
  const values = {}
  for (let i = 0; i < 9; i++) values[`VAR_${i}`] = `value ${i}`
  const result = await seal({ values, keys: { v1: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=' }, targets: ['netlify', 'op://V/I'], exec, onWrite: (event) => events.push(`${event.target}:${event.name}`) })
  const names = Object.keys(values)
  assert.equal(events, [...names.map((name) => `netlify:${name}`), ...names.map((name) => `1password:${name}`)])
  assert.equal(result.written.map((event) => event.name), [...names, ...names])
  assert.is(exec.calls.filter((call) => call.cmd === 'netlify').length, 9)
  assert.is(exec.calls.filter((call) => call.cmd === 'op').length, 1)
})

test('check: many names cost one call, and the report keeps the order given', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const keys = readKeyFile(findKeyFile(dir))
  const stored = { GOOD: encrypt('a', keys), PLAIN: 'plain', ALSO_GOOD: encrypt('b', keys) }
  const exec = fakeExec((cmd, args) => (args[0] === 'env:list' ? JSON.stringify(stored) : '{}'))
  const result = await cli(['check', 'GOOD', 'MISSING', 'PLAIN', 'ALSO_GOOD', '--to', 'netlify'], { cwd: dir, exec })
  assert.is(result.code, 1)
  assert.equal(result.stderr.trim().split('\n').map((line) => line.split(' ').slice(0, 2).join(' ')), ['✔ GOOD', '✖ MISSING', '✖ PLAIN', '✔ ALSO_GOOD'])
  assert.equal(exec.calls.map((call) => call.args[0]), ['env:list', 'env:get'])
})

test('reseal: one read, one write, and lines in the order given, up to the first name that fails', async () => {
  const dir = tmpProject({ 'package.json': {} })
  await cli(['init'], { cwd: dir })
  const v1 = readKeyFile(findKeyFile(dir))
  await cli(['rotate'], { cwd: dir })
  const keys = readKeyFile(findKeyFile(dir))
  const fields = (map) => item(Object.keys(map).map((label, i) => ({ id: `f${i}`, type: 'CONCEALED', label, value: map[label] })))
  const stored = { OLD: encrypt('old', v1), NEW: encrypt('new', keys), PLAIN: 'plain', LATER: encrypt('later', v1) }
  const exec = fakeExec((cmd, args) => {
    if (args[1] === 'get') return fields(stored)
    if (args[0] === 'read') return { code: 1, stderr: "item 'V/I' does not have a field 'MISSING'" }
    return ''
  })
  const result = await cli(['reseal', 'OLD', 'NEW', 'PLAIN', 'MISSING', 'LATER', '--to', 'op://V/I'], { cwd: dir, exec })
  assert.is(result.code, 1)
  assert.equal(result.stderr.trim().split('\n').map((line) => line.replace(/ in 1Password \(.*?\)/, '')), [
    '✔ OLD: v1 → v2',
    '- NEW: already encrypted with v2',
    '✔ PLAIN: plaintext → v2',
    'preseal: MISSING is not set'
  ])
  const edits = exec.calls.filter((call) => call.args[1] === 'edit')
  assert.is(edits.length, 1)
  const written = edits[0].args.slice(5).map((arg) => arg.split('[concealed]='))
  assert.equal(written.map(([name]) => name), ['OLD', 'PLAIN'])
  assert.equal(written.map(([, value]) => [versionOf(value), decrypt(value, keys)]), [['v2', 'old'], ['v2', 'plain']])
})

test('reseal: a name given twice still sees its own first write', async () => {
  const dir = tmpProject({ 'package.json': {}, '.env.out': 'A=plain\n' })
  await cli(['init'], { cwd: dir })
  const result = await cli(['reseal', 'A', 'A', '--to', 'dotenv:.env.out'], { cwd: dir })
  assert.is(result.code, 0)
  assert.match(result.stderr, /✔ A in .*: plaintext → v1\n- A in .*: already encrypted with v1\n/)
})

test.run()
