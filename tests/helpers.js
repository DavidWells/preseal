const fs = require('fs')
const os = require('os')
const path = require('path')

const created = []
process.on('exit', () => {
  for (const dir of created) fs.rmSync(dir, { recursive: true, force: true })
})

/** A fresh temp project directory. Removed on process exit. */
function tmpProject(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'preseal-test-'))
  for (const name of Object.keys(files)) {
    const file = path.join(dir, name)
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, typeof files[name] === 'string' ? files[name] : JSON.stringify(files[name], null, 2))
  }
  created.push(dir)
  return dir
}

/**
 * A recording stand-in for the exec port.
 * `handler(cmd, args, opts)` may return { stdout, stderr, code } or a string (stdout).
 * Missing binaries are simulated by listing them in `missing`.
 */
function fakeExec(handler = () => '', { missing = [] } = {}) {
  const calls = []
  async function exec(cmd, args, opts = {}) {
    calls.push({ cmd, args, opts })
    if (missing.includes(cmd)) {
      const err = new Error(`preseal: \`${cmd}\` was not found on your PATH.`)
      err.code = 'ENOENT'
      throw err
    }
    const result = (await handler(cmd, args, opts)) || ''
    const full = typeof result === 'string' ? { stdout: result, stderr: '', code: 0 } : Object.assign({ stdout: '', stderr: '', code: 0 }, result)
    if (full.code !== 0 && !opts.allowFail) throw new Error(`preseal: \`${cmd}\` failed (exit ${full.code}):\n${full.stderr}`)
    return full
  }
  exec.calls = calls
  return exec
}

module.exports = { tmpProject, fakeExec }
