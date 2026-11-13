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

// The agent skill is published with the package, so `node_modules/preseal/skill` exists.
test('the agent skill ships in the package and names itself', () => {
  assert.ok(pkg.files.includes('skill'))
  const text = fs.readFileSync(path.join(__dirname, '../skill/SKILL.md'), 'utf8')
  const front = /^---\nname: (\S+)\ndescription: (.+)\n---\n/.exec(text)
  assert.ok(front, 'frontmatter with name and description')
  assert.is(front[1], pkg.name)
  assert.ok(front[2].length > 80 && front[2].length < 1024, 'a description an agent can match on')
  // Hints an agent would copy must not teach the unsafe forms.
  for (const block of text.matchAll(/```bash\n([\s\S]*?)```/g)) {
    assert.not.match(block[1], /--value|preseal decrypt|--force/)
  }
})

test.run()
