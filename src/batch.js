/*
Every external call is a CLI process (`netlify`, `aws`, `op`) that costs
hundreds of milliseconds, so the number of calls is what a command costs.
These helpers turn N calls into one where the store allows it, and keep the
results in the order the names were given.
*/

/**
 * @typedef {object} ReadResult
 * @property {string} [value] - the stored value, undefined when it is not set
 * @property {Error} [error] - why this one name could not be read
 */

/**
 * @param {import('./adapters').Adapter} adapter
 * @param {string} name
 * @returns {Promise<ReadResult>}
 */
async function readOne(adapter, name) {
  try {
    return { value: await adapter.get(name) }
  } catch (error) {
    return { error }
  }
}

/**
 * Read several names from an adapter: one batched call when the adapter has
 * `getMany`, otherwise one `get` per name. Never throws; each entry carries
 * its own value or error, in the order of `names`.
 *
 * @param {import('./adapters').Adapter} adapter
 * @param {string[]} names
 * @returns {Promise<ReadResult[]>}
 */
async function readMany(adapter, names) {
  if (adapter.getMany && names.length > 1) return adapter.getMany(names)
  const results = []
  for (const name of names) results.push(await readOne(adapter, name))
  return results
}

/**
 * Write several values to an adapter: one batched call when the adapter has
 * `setMany`, a few `set` calls at a time when it allows `concurrency`,
 * otherwise one `set` after another.
 *
 * `onWritten(index)` is called for each entry, in order, once it and every
 * entry before it are stored. On a failure, the error of the earliest failed
 * entry is thrown after the calls already running have finished.
 *
 * @param {import('./adapters').Adapter} adapter
 * @param {[string, string][]} entries - [name, value] pairs
 * @param {(index: number) => void} [onWritten]
 * @returns {Promise<void>}
 */
async function writeMany(adapter, entries, onWritten = () => {}) {
  if (adapter.setMany && entries.length > 1) {
    await adapter.setMany(entries)
    entries.forEach((entry, index) => onWritten(index))
    return
  }
  const workers = Math.min(adapter.concurrency || 1, entries.length - 1)
  if (workers <= 1) {
    for (let index = 0; index < entries.length; index++) {
      await adapter.set(entries[index][0], entries[index][1])
      onWritten(index)
    }
    return
  }

  // The first write goes alone. A setup problem (not logged in, nothing
  // linked, tool missing) then fails once, with nothing else in flight.
  await adapter.set(entries[0][0], entries[0][1])
  onWritten(0)

  const stored = [true]
  let reported = 1
  let next = 1
  /** @type {{ index: number, error: Error } | null} */
  let failure = null
  async function worker() {
    while (next < entries.length && !failure) {
      const index = next++
      try {
        await adapter.set(entries[index][0], entries[index][1])
        stored[index] = true
        while (stored[reported]) onWritten(reported++)
      } catch (error) {
        if (!failure || index < failure.index) failure = { index, error }
      }
    }
  }
  await Promise.all(Array.from({ length: workers }, worker))
  if (failure) throw failure.error
}

/**
 * Run `fn` over `items`, at most `limit` at a time. Resolves when all are done.
 *
 * @template T
 * @param {T[]} items
 * @param {number} limit
 * @param {(item: T) => Promise<void>} fn
 * @returns {Promise<void>}
 */
async function eachLimit(items, limit, fn) {
  let next = 0
  async function worker() {
    while (next < items.length) await fn(items[next++])
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
}

module.exports = { readOne, readMany, writeMany, eachLimit }
