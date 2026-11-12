const { test } = require('uvu')
const assert = require('uvu/assert')
const fs = require('fs')
const path = require('path')
const pkg = require('../package.json')

// TypeScript's node16 and bundler resolution read types from `exports` only.
// Without a `types` entry next to each module, an import is an implicit any.
test('every exported module names its type declarations', () => {
  const modules = Object.keys(pkg.exports).filter((key) => key !== './package.json')
  assert.ok(modules.length >= 3)
  for (const key of modules) {
    const entry = pkg.exports[key]
    assert.ok(fs.existsSync(path.join(__dirname, '..', entry.default)), `${key}: ${entry.default} exists`)
    // `tsc --outDir types` mirrors src/, so src/seal.js is described by types/seal.d.ts.
    assert.is(entry.types, entry.default.replace(/^\.\/src\//, './types/').replace(/\.js$/, '.d.ts'), `${key}: types`)
    assert.equal(Object.keys(entry), ['types', 'default'], `${key}: types comes first`)
  }
  assert.is(`./${pkg.types}`, pkg.exports['.'].types)
  assert.is(`./${pkg.main}`, pkg.exports['.'].default)
})

// The older `moduleResolution: node` ignores `exports`, so subpaths are mapped here too.
test('typesVersions covers every subpath for older TypeScript resolution', () => {
  const subpaths = Object.keys(pkg.exports).filter((key) => key !== '.' && key !== './package.json')
  const mapped = pkg.typesVersions['*']
  assert.equal(Object.keys(mapped).sort(), subpaths.map((key) => key.slice(2)).sort())
  for (const key of subpaths) {
    assert.equal(mapped[key.slice(2)], [pkg.exports[key].types.slice(2)], key)
  }
})

test.run()
