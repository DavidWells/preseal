const fs = require('fs')
const path = require('path')
const { parseDotenv, upsertDotenv } = require('../dotenv')

/**
 * A dotenv file on disk. Handy for hosts without an API here (paste the file
 * into their dashboard) and for committing encrypted values next to the code.
 *
 * @param {object} opts
 * @param {string} opts.file
 * @param {string} [opts.cwd]
 * @returns {import('./index').Adapter}
 */
function createDotenvAdapter(opts) {
  if (!opts || !opts.file) throw new Error('preseal: the dotenv target needs a file, like dotenv:.env.production')
  const file = path.resolve(opts.cwd || process.cwd(), opts.file)

  function read() {
    try {
      return fs.readFileSync(file, 'utf8')
    } catch (err) {
      return ''
    }
  }

  return {
    name: 'dotenv',
    label: `dotenv file (${opts.file})`,
    async set(name, value) {
      fs.mkdirSync(path.dirname(file), { recursive: true })
      fs.writeFileSync(file, upsertDotenv(read(), name, value))
    },
    async get(name) {
      return parseDotenv(read())[name]
    }
  }
}

module.exports = { createDotenvAdapter }
