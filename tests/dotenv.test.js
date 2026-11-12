const { test } = require('uvu')
const assert = require('uvu/assert')
const { parseDotenv, upsertDotenv } = require('../src/dotenv')

test('parseDotenv handles the usual shapes', () => {
  const parsed = parseDotenv([
    '# comment',
    'PLAIN=value',
    'export EXPORTED=yes',
    'SPACED = spaced out ',
    'QUOTED="has # hash and = sign"',
    "SINGLE='single $quoted'",
    'MULTI="line1\\nline2"',
    'INLINE=value # trailing comment',
    'EMPTY=',
    'SEALED=enc:v1:abc+/def==',
    'URL=postgres://u:p@host:5432/db?ssl=true',
    ''
  ].join('\n'))
  assert.equal(parsed, {
    PLAIN: 'value',
    EXPORTED: 'yes',
    SPACED: 'spaced out',
    QUOTED: 'has # hash and = sign',
    SINGLE: 'single $quoted',
    MULTI: 'line1\nline2',
    INLINE: 'value',
    EMPTY: '',
    SEALED: 'enc:v1:abc+/def==',
    URL: 'postgres://u:p@host:5432/db?ssl=true'
  })
})

test('parseDotenv reads quoted values that span lines', () => {
  assert.equal(parseDotenv('KEY="-----BEGIN-----\nabc\n-----END-----"\nNEXT=1\n'), {
    KEY: '-----BEGIN-----\nabc\n-----END-----',
    NEXT: '1'
  })
})

test('upsertDotenv appends, replaces and keeps other lines', () => {
  let text = upsertDotenv('', 'A', 'enc:v1:aaa=')
  assert.is(text, 'A=enc:v1:aaa=\n')
  text = upsertDotenv('# header\nA=old\nexport B=keep', 'A', 'enc:v1:new+/=')
  assert.is(text, '# header\nA=enc:v1:new+/=\nexport B=keep')
  text = upsertDotenv(text, 'C', 'enc:v1:ccc')
  assert.is(text, '# header\nA=enc:v1:new+/=\nexport B=keep\nC=enc:v1:ccc\n')
  assert.is(upsertDotenv('export B=old\n', 'B', 'new'), 'export B=new\n')
})

test('upsertDotenv does not confuse names that share a prefix', () => {
  assert.is(upsertDotenv('API_KEY_OLD=1\n', 'API_KEY', '2'), 'API_KEY_OLD=1\nAPI_KEY=2\n')
})

test('upsertDotenv quotes values that need it, and they parse back', () => {
  for (const value of ['has space "and quotes" $1 #hash\nnewline', "it's got 'single' quotes\nand a newline", 'both \' and " here']) {
    assert.equal(parseDotenv(upsertDotenv('', 'TRICKY', value)), { TRICKY: value })
  }
  assert.throws(() => upsertDotenv('', 'TRICKY', '\' " `'), /every quote character/)
})

test.run()
