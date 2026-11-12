const fs = require('fs')
const { spawn } = require('child_process')

const INSTALL_HINTS = {
  op: 'Install the 1Password CLI: https://developer.1password.com/docs/cli/get-started',
  aws: 'Install the AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html',
  netlify: 'Install the Netlify CLI: npm install -g netlify-cli'
}

/**
 * @typedef {object} ExecResult
 * @property {string} stdout
 * @property {string} stderr
 * @property {number} code
 */

/**
 * @typedef {(cmd: string, args: string[], opts?: { input?: string, allowFail?: boolean, env?: Record<string, string>, cwd?: string }) => Promise<ExecResult>} Exec
 * The one port every adapter talks through. Swap it in tests to record calls.
 */

/**
 * Run a command without a shell. Rejects on a non-zero exit unless `allowFail` is set.
 * @type {Exec}
 */
function exec(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      env: opts.env || process.env,
      cwd: opts.cwd,
      stdio: ['pipe', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', (err) => {
      // spawn reports a missing working directory as ENOENT too.
      if (/** @type {any} */ (err).code === 'ENOENT' && opts.cwd && !fs.existsSync(opts.cwd)) {
        return reject(new Error(`preseal: cannot run \`${cmd}\` in ${opts.cwd}: no such directory`))
      }
      if (/** @type {any} */ (err).code === 'ENOENT') {
        const hint = INSTALL_HINTS[cmd] ? ` ${INSTALL_HINTS[cmd]}` : ''
        return reject(Object.assign(new Error(`preseal: \`${cmd}\` was not found on your PATH.${hint}`), { code: 'ENOENT' }))
      }
      reject(err)
    })
    child.on('close', (code) => {
      if (code !== 0 && !opts.allowFail) {
        const detail = (stderr.trim() || stdout.trim()).split('\n').slice(-6).join('\n')
        return reject(new Error(`preseal: \`${cmd} ${args.slice(0, 2).join(' ')}\` failed (exit ${code})${detail ? `:\n${detail}` : ''}`))
      }
      resolve({ stdout, stderr, code })
    })
    // A child that exits before reading stdin must not crash us with EPIPE.
    child.stdin.on('error', () => {})
    child.stdin.end(opts.input || '')
  })
}

/**
 * The same port, with every command run in `cwd`. The netlify CLI finds its
 * linked site there, and aws and op read their local config from it.
 * @param {Exec} run
 * @param {string} [cwd]
 * @returns {Exec}
 */
function execIn(run, cwd) {
  if (!cwd) return run
  return (cmd, args, opts) => run(cmd, args, Object.assign({ cwd }, opts))
}

module.exports = { exec, execIn }
