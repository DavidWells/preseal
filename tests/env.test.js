const { test } = require('uvu')
const assert = require('uvu/assert')
const { createEnv, encrypt, generateKey } = require('../src/index')

const KEYS = { v1: generateKey() }

test('env() decrypts encrypted values and passes plaintext through', () => {
  const source = { SECRET: encrypt('s3cret', KEYS), NODE_ENV: 'production' }
  const env = createEnv(KEYS, { source })
  assert.is(env('SECRET'), 's3cret')
  assert.is(env('NODE_ENV'), 'production')
  assert.is(env('MISSING'), undefined)
})

test('env() reads process.env by default', () => {
  process.env.PRESEAL_TEST_VALUE = encrypt('from process.env', KEYS)
  try {
    assert.is(createEnv(KEYS)('PRESEAL_TEST_VALUE'), 'from process.env')
  } finally {
    delete process.env.PRESEAL_TEST_VALUE
  }
})

test('a single base64 key is treated as v1', () => {
  const source = { SECRET: encrypt('s3cret', KEYS.v1) }
  assert.is(createEnv(KEYS.v1, { source })('SECRET'), 's3cret')
})

test('fallback applies to unset and empty values only', () => {
  const env = createEnv(KEYS, { source: { EMPTY: '', SET: 'x' } })
  assert.is(env('MISSING', 'fallback'), 'fallback')
  assert.is(env('EMPTY', 'fallback'), 'fallback')
  assert.is(env('EMPTY'), '')
  assert.is(env('SET', 'fallback'), 'x')
})

test('env.required throws when unset', () => {
  const env = createEnv(KEYS, { source: { SET: encrypt('x', KEYS), EMPTY: '' } })
  assert.is(env.required('SET'), 'x')
  assert.throws(() => env.required('MISSING'), /MISSING is not set/)
  assert.throws(() => env.required('EMPTY'), /EMPTY is not set/)
})

test('a value that changes is decrypted again', () => {
  const source = { SECRET: encrypt('one', KEYS) }
  const env = createEnv(KEYS, { source })
  assert.is(env('SECRET'), 'one')
  source.SECRET = encrypt('two', KEYS)
  assert.is(env('SECRET'), 'two')
})

test('decrypt errors name the variable, not the value', () => {
  const sealed = encrypt('s3cret', generateKey())
  const env = createEnv(KEYS, { source: { STRIPE_SECRET_KEY: sealed } })
  try {
    env('STRIPE_SECRET_KEY')
    assert.unreachable()
  } catch (err) {
    assert.match(err.message, /^preseal: STRIPE_SECRET_KEY: could not decrypt/)
    assert.not.match(err.message, sealed)
  }
})

test('env.all returns decrypted values for the encrypted variables', () => {
  const source = { A: encrypt('a', KEYS), B: 'plain', C: encrypt('c', KEYS) }
  const env = createEnv(KEYS, { source })
  assert.equal(env.all(), { A: 'a', C: 'c' })
  assert.equal(env.all(['A', 'B', 'NOPE']), { A: 'a', B: 'plain', NOPE: undefined })
})

test('env.inject replaces encrypted values in place', () => {
  const source = { A: encrypt('a', KEYS), B: 'plain' }
  const env = createEnv(KEYS, { source })
  assert.equal(env.inject(), ['A'])
  assert.equal(source, { A: 'a', B: 'plain' })
})

test('env.inject leaves the target untouched when one value is bad', () => {
  const good = encrypt('a', KEYS)
  const bad = encrypt('b', generateKey())
  const target = { A: good, B: bad }
  const env = createEnv(KEYS, { source: {} })
  assert.throws(() => env.inject(target), /could not decrypt/)
  assert.equal(target, { A: good, B: bad })
})

test('createEnv rejects a bad key at startup', () => {
  assert.throws(() => createEnv('not-a-key'), /must be 32 bytes/)
  assert.throws(() => createEnv({}), /no key given/)
})

test.run()
