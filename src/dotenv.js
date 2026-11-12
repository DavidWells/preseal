// Line matcher adapted from dotenv (BSD-2-Clause, https://github.com/motdotla/dotenv).
const LINE = /^\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?$/mg

/**
 * Parse dotenv text into an ordered map.
 * @param {string} text
 * @returns {Record<string, string>}
 */
function parseDotenv(text) {
  /** @type {Record<string, string>} */
  const out = {}
  const src = text.replace(/\r\n?/g, '\n')
  let match
  LINE.lastIndex = 0
  while ((match = LINE.exec(src)) !== null) {
    let value = (match[2] || '').trim()
    const quote = value[0]
    value = value.replace(/^(['"`])([\s\S]*)\1$/, '$2')
    if (quote === '"') value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r')
    out[match[1]] = value
  }
  return out
}

// dotenv does not unescape quotes, so wrap in a quote character the value does not contain.
function quote(name, value) {
  const mark = ["'", '"', '`'].find((char) => !value.includes(char))
  if (!mark) throw new Error(`preseal: ${name} contains every quote character and cannot be written to a dotenv file`)
  return `${mark}${mark === '"' ? value.replace(/\n/g, '\\n') : value}${mark}`
}

/**
 * Set `NAME=value` in dotenv text, replacing an existing line or appending.
 * @param {string} text
 * @param {string} name
 * @param {string} value
 * @returns {string}
 */
function upsertDotenv(text, name, value) {
  const safe = /^[\w:/+=.@-]*$/.test(value) ? value : quote(name, value)
  const line = `${name}=${safe}`
  const existing = new RegExp(`^(\\s*(?:export\\s+)?)${name.replace(/[.-]/g, '\\$&')}\\s*=.*$`, 'm')
  if (existing.test(text)) return text.replace(existing, (_, lead) => `${lead}${line}`)
  const sep = text && !text.endsWith('\n') ? '\n' : ''
  return `${text}${sep}${line}\n`
}

module.exports = { parseDotenv, upsertDotenv }
