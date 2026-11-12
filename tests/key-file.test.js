const { test } = require('uvu')
const assert = require('uvu/assert')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')
const { encrypt, generateKey } = require('../src/crypto')
const keyFile = require('../src/key-file')
const { tmpProject } = require('./helpers')

const KEYS = { v1: generateKey() }

test('every flavor renders keys that parse back out', () => {
  for (const format of ['cjs', 'esm', 'ts']) {
    for (const standalone of [true, false]) {
      const source = keyFile.renderKeyFile({ keys: KEYS, format, standalone })
      assert.equal(keyFile.parseKeys(source), KEYS, `${format} standalone=${standalone}`)
    }
  }
})

test('linked flavors import createEnv, standalone flavors import only crypto', () => {
  assert.match(keyFile.renderKeyFile({ keys: KEYS, format: 'cjs' }), "require('preseal')")
  assert.match(keyFile.renderKeyFile({ keys: KEYS, format: 'esm' }), "import { createEnv } from 'preseal'")
  const standalone = keyFile.renderKeyFile({ keys: KEYS, format: 'cjs', standalone: true })
  assert.not.match(standalone, 'preseal\')')
  assert.match(standalone, "require('crypto')")
})

test('the standalone cjs module decrypts with no dependency', () => {
  const dir = tmpProject({ 'env-key.js': keyFile.renderKeyFile({ keys: KEYS, format: 'cjs', standalone: true }) })
  const out = execFileSync(process.execPath, ['-e', "process.stdout.write(require('./env-key').env('SECRET') + '|' + require('./env-key').env('PLAIN'))"], {
    cwd: dir,
    env: Object.assign({}, process.env, { SECRET: encrypt('s3cret ✓', KEYS), PLAIN: 'plain' })
  })
  assert.is(out.toString(), 's3cret ✓|plain')
})

test('the standalone esm module decrypts with no dependency', () => {
  const dir = tmpProject({
    'env-key.mjs': keyFile.renderKeyFile({ keys: KEYS, format: 'esm', standalone: true }),
    'main.mjs': "import { env } from './env-key.mjs'\nprocess.stdout.write(env('SECRET'))\n"
  })
  const out = execFileSync(process.execPath, ['main.mjs'], {
    cwd: dir,
    env: Object.assign({}, process.env, { SECRET: encrypt('esm works', KEYS) })
  })
  assert.is(out.toString(), 'esm works')
})

test('the linked cjs module works when the package resolves', () => {
  const dir = tmpProject({ 'env-key.js': keyFile.renderKeyFile({ keys: KEYS, format: 'cjs' }) })
  const pkgDir = path.join(dir, 'node_modules')
  fs.mkdirSync(pkgDir)
  fs.symlinkSync(path.resolve(__dirname, '..'), path.join(pkgDir, 'preseal'), 'dir')
  const out = execFileSync(process.execPath, ['-e', "process.stdout.write(require('./env-key').env.required('SECRET'))"], {
    cwd: dir,
    env: Object.assign({}, process.env, { SECRET: encrypt('linked', KEYS) })
  })
  assert.is(out.toString(), 'linked')
})

test('the generated module refuses to load where a document global exists', () => {
  const dir = tmpProject({ 'env-key.js': keyFile.renderKeyFile({ keys: KEYS, format: 'cjs', standalone: true }) })
  assert.throws(() => execFileSync(process.execPath, ['-e', "globalThis.document = {}; require('./env-key')"], { cwd: dir, stdio: 'pipe' }), /browser code/)
})

test('detectFormat reads the project', () => {
  assert.is(keyFile.detectFormat(tmpProject({ 'package.json': {} })), 'cjs')
  assert.is(keyFile.detectFormat(tmpProject({ 'package.json': { type: 'module' } })), 'esm')
  assert.is(keyFile.detectFormat(tmpProject({ 'package.json': { type: 'module' }, 'tsconfig.json': {} })), 'ts')
  assert.is(keyFile.detectFormat(tmpProject()), 'cjs')
})

test('defaultKeyFilePath prefers src/ and picks an extension node will load', () => {
  const rel = (dir, format) => path.relative(dir, keyFile.defaultKeyFilePath(dir, format))
  const plain = tmpProject({ 'package.json': {} })
  assert.is(rel(plain, 'cjs'), 'env-key.js')
  assert.is(rel(plain, 'esm'), 'env-key.mjs')
  const withSrc = tmpProject({ 'package.json': { type: 'module' }, 'src/index.js': '' })
  assert.is(rel(withSrc, 'esm'), path.join('src', 'env-key.js'))
  assert.is(rel(withSrc, 'cjs'), path.join('src', 'env-key.cjs'))
  assert.is(rel(withSrc, 'ts'), path.join('src', 'env-key.ts'))
})

test('createKeyFile writes a loadable file and refuses to overwrite it', () => {
  const dir = tmpProject({ 'package.json': {} })
  const created = keyFile.createKeyFile({ cwd: dir, standalone: true })
  assert.is(path.relative(dir, created.file), 'env-key.js')
  assert.equal(keyFile.readKeyFile(created.file), created.keys)
  assert.is(keyFile.findKeyFile(dir), created.file)
  assert.throws(() => keyFile.createKeyFile({ cwd: dir }), /already exists/)
  const forced = keyFile.createKeyFile({ cwd: dir, force: true })
  assert.is.not(forced.keys.v1, created.keys.v1)
})

test('a custom key file location is remembered in package.json', () => {
  const dir = tmpProject({ 'package.json': '{\n\t"name": "app"\n}\n' })
  const created = keyFile.createKeyFile({ cwd: dir, file: 'server/secrets/key.js', standalone: true })
  const pkgText = fs.readFileSync(path.join(dir, 'package.json'), 'utf8')
  assert.equal(JSON.parse(pkgText)['preseal'], { keyFile: 'server/secrets/key.js' })
  assert.match(pkgText, /^\t"name"/m)
  assert.ok(pkgText.endsWith('}\n'))
  assert.is(keyFile.findKeyFile(dir), created.file)
})

test('the default location leaves package.json alone', () => {
  const dir = tmpProject({ 'package.json': '{"name":"app"}' })
  keyFile.createKeyFile({ cwd: dir, standalone: true })
  assert.is(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'), '{"name":"app"}')
})

test('findKeyFile: explicit path wins, null when nothing is there', () => {
  const dir = tmpProject({ 'package.json': {} })
  assert.is(keyFile.findKeyFile(dir), null)
  assert.is(keyFile.findKeyFile(dir, 'custom.js'), path.join(dir, 'custom.js'))
})

test('readKeyFile explains a missing or keyless file', () => {
  const dir = tmpProject({ 'empty.js': 'module.exports = {}' })
  assert.throws(() => keyFile.readKeyFile(path.join(dir, 'nope.js')), /key file not found/)
  assert.throws(() => keyFile.readKeyFile(path.join(dir, 'empty.js')), /no keys found/)
})

test('addKey appends after the last key and keeps the file valid', () => {
  const v2 = generateKey()
  const source = keyFile.renderKeyFile({ keys: KEYS, format: 'cjs', standalone: true })
  const next = keyFile.addKey(source, 'v2', v2)
  assert.equal(keyFile.parseKeys(next), { v1: KEYS.v1, v2 })
  assert.throws(() => keyFile.addKey(next, 'v2', v2), /already in the key file/)
})

test('addKey copes with hand-edited files: no trailing comma, double quotes', () => {
  const v2 = generateKey()
  const source = `const ENV_KEYS = {\n    v1: "${KEYS.v1}"\n}\nmodule.exports = { ENV_KEYS }\n`
  const next = keyFile.addKey(source, 'v2', v2)
  assert.match(next, `    v1: "${KEYS.v1}",\n    v2: "${v2}",\n}`)
  const dir = tmpProject({ 'k.js': next })
  assert.equal(require(path.join(dir, 'k.js')).ENV_KEYS, { v1: KEYS.v1, v2 })
})

test('rotateKeyFile adds the next version and old values still decrypt', () => {
  const dir = tmpProject({ 'package.json': {} })
  const created = keyFile.createKeyFile({ cwd: dir, standalone: true })
  const old = encrypt('before rotation', created.keys)
  const rotated = keyFile.rotateKeyFile(created.file)
  assert.is(rotated.version, 'v2')
  assert.equal(Object.keys(keyFile.readKeyFile(created.file)), ['v1', 'v2'])
  const mod = require(created.file)
  process.env.PRESEAL_ROTATE_OLD = old
  process.env.PRESEAL_ROTATE_NEW = encrypt('after rotation', rotated.keys)
  try {
    assert.is(mod.env('PRESEAL_ROTATE_OLD'), 'before rotation')
    assert.is(mod.env('PRESEAL_ROTATE_NEW'), 'after rotation')
    assert.ok(process.env.PRESEAL_ROTATE_NEW.startsWith('enc:v2:'))
  } finally {
    delete process.env.PRESEAL_ROTATE_OLD
    delete process.env.PRESEAL_ROTATE_NEW
  }
})

test.run()
