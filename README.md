# preseal

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![Node 18.3 or newer](https://img.shields.io/badge/node-%3E%3D18.3-brightgreen.svg)
![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)

Encrypt env vars before your host sees them. The host stores ciphertext, the key lives in your repo, and your code decrypts in memory at runtime.

preseal is the tool for the approach in the post [Encrypt env vars before your host sees them](https://davidwells.io/blog/encrypt-env-vars-before-your-host-sees-them).

> **This is not a silver bullet.** preseal makes one kind of leak less damaging: someone who gets only your host's env var store sees ciphertext. It does nothing against an attacker who also has your code, or who can run code inside your app. [Read the post](https://davidwells.io/blog/encrypt-env-vars-before-your-host-sees-them) for how it helps and where it stops, and see [What this protects against](#what-this-protects-against-and-what-it-doesnt) below.

```bash
npx preseal set STRIPE_SECRET_KEY --to netlify
```

That one command creates a key file, asks for the value with a hidden prompt, encrypts it, and sets `STRIPE_SECRET_KEY=enc:v1:...` on your linked Netlify site.

## TL;DR

**The problem:** your host's env var store holds every production secret in plaintext. One leak of that store (a breach at the host, an admin tool, a build log, a screenshot of the settings page) hands over all of them at once.

**The solution:** encrypt each value before it leaves your machine. The host (Netlify, AWS SSM, 1Password) only ever stores `enc:v1:...`. The decryption key lives in a source file in your repo. An attacker now needs the host's store and your code.

This package automates the trick from [Encrypt env vars before your host sees them](https://davidwells.io/blog/encrypt-env-vars-before-your-host-sees-them). The value format is the same as in the post, so the two are interchangeable.

### Why use preseal?

| Feature | What it does |
| --- | --- |
| **One command** | `preseal set NAME --to netlify` creates the key, reads the value, encrypts it and stores the ciphertext. |
| **Three stores built in** | Netlify env vars, AWS SSM Parameter Store and 1Password, plus dotenv files and stdout for every other host. |
| **Plaintext stays out of your shell** | Values come from a hidden prompt, stdin, or straight from `op://` and `ssm:` references. Only ciphertext is ever passed to another program. |
| **Nothing to install at runtime** | The generated key file is about 40 lines on Node's built-in `crypto`. Your app does not depend on this package. |
| **Local dev unchanged** | Values without the `enc:` prefix pass through, so `.env` files and plain config like `NODE_ENV` keep working. |
| **Key rotation** | `rotate` adds a `v2` key, `reseal` re-encrypts stored values in place, and old keys keep decrypting until you delete them. |
| **Verifiable** | `check` confirms a stored value decrypts with the key in your repo, without printing it. It exits 1 when it doesn't, so it works in CI. |
| **Batched** | Checking 20 Netlify variables is one CLI call (about 1.5 s), not 20. |

## Quick example

Examples write `preseal` for short. Without installing anything, use `npx preseal`.

```bash
# Encrypt a value and store it. The first run also creates src/env-key.js.
preseal set STRIPE_SECRET_KEY --to netlify
#   STRIPE_SECRET_KEY: (hidden prompt)
#   ✔ STRIPE_SECRET_KEY → Netlify (linked site, all contexts)  (key v1)

# Pull the plaintext from 1Password and store the ciphertext in two places.
preseal set DATABASE_URL --from op://Engineering/Postgres/url --to netlify --to ssm:/my-app/prod
#   ✔ DATABASE_URL → Netlify (linked site, all contexts)  (key v1)
#   ✔ DATABASE_URL → AWS SSM (/my-app/prod/<NAME>, SecureString)  (key v1)

# Encrypt a whole dotenv file, leaving public config alone.
preseal push .env.production --to netlify --except 'NODE_ENV,*_PUBLIC_*'

# Convert a plaintext variable that is already on the host.
preseal reseal LEGACY_TOKEN --to netlify
#   ✔ LEGACY_TOKEN in Netlify (linked site, all contexts): plaintext → v1

# Confirm what is stored decrypts with the key in your repo.
preseal check STRIPE_SECRET_KEY DATABASE_URL --to netlify
#   ✔ STRIPE_SECRET_KEY in Netlify (linked site, context dev): decrypts with key v1
#   ✔ DATABASE_URL in Netlify (linked site, context dev): decrypts with key v1

# Rotate: add key v2, then re-encrypt what is stored.
preseal rotate
preseal reseal STRIPE_SECRET_KEY DATABASE_URL --to netlify
#   ✔ STRIPE_SECRET_KEY in Netlify (linked site, all contexts): v1 → v2
#   ✔ DATABASE_URL in Netlify (linked site, all contexts): v1 → v2
```

Then read the values in server code:

```js
const { env } = require('./src/env-key')

const stripe = require('stripe')(env('STRIPE_SECRET_KEY'))
```

## How it works

```
                          your machine
┌──────────────────────────────────────────────────────────────┐
│  plaintext ───────▶ preseal ────────▶ enc:v1:9f2c...         │
│  (hidden prompt,       ▲                   │                 │
│   stdin, op://, ssm:)  │ key               │                 │
│                 src/env-key.js             │                 │
└────────────────────────┬───────────────────┼─────────────────┘
                git push │                   │ netlify, aws or op CLI
                         ▼                   ▼
      ┌──────────────────────────┐  ┌──────────────────────────┐
      │ your repo                │  │ your host                │
      │ holds the key            │  │ holds the ciphertext     │
      └─────────────┬────────────┘  └─────────────┬────────────┘
             deploy │                             │ process.env
                    ▼                             ▼
      ┌────────────────────────────────────────────────────────┐
      │ your running app                                       │
      │ env('STRIPE_SECRET_KEY') → plaintext, in memory        │
      └────────────────────────────────────────────────────────┘
```

The key and the ciphertext travel by different routes and only meet inside your running process. preseal never writes the plaintext anywhere.

Inside the package, every store is an adapter behind one small interface, and every adapter reaches its store through one `exec` function that runs a CLI without a shell:

| File | Job |
| --- | --- |
| `src/index.js` | The runtime: `createEnv`, `encrypt`, `decrypt`. Loads only `crypto`. |
| `src/crypto.js` | AES-256-GCM and key versions |
| `src/key-file.js` | Creates, finds and rotates the key file. Edits it as text and never executes it. |
| `src/sources.js` | Reads plaintext from `op://`, `ssm:`, `env:` and `file:` |
| `src/seal.js`, `src/batch.js` | Encrypt, then write to each target with batching and bounded concurrency |
| `src/adapters/*.js` | Netlify, SSM, 1Password, dotenv, stdout |
| `src/exec.js` | The one place a child process is started |

## Design principles

**Two places, two leaks.** The ciphertext is on the host and the key is in the repo. Neither is useful alone, so one leak is no longer a full compromise.

**Your app owes the tool nothing.** The generated key file is self-contained and the value format is documented below. Delete this package tomorrow and your app keeps decrypting.

**Plaintext stays out of your terminal.** The default input is a hidden prompt. Better, `--from op://...` moves a value from 1Password to your host without it ever appearing on screen, in `argv` or in shell history. Other programs only ever receive ciphertext.

**Use the CLIs you already trust.** The adapters call `netlify`, `aws` and `op` with whatever login each one has. preseal stores no tokens, bundles no SDKs and has no dependencies.

**Safe to run twice.** Commands can be repeated. `reseal` skips values that are already on the newest key, `init` refuses to overwrite a key file, a Netlify secret that would read back masked is refused, and `--dry-run` shows the plan first.

## How preseal compares

| | preseal | Plain host env vars | [dotenvx](https://github.com/dotenvx/dotenvx) | [SOPS](https://github.com/getsops/sops) | Cloud secret manager |
| --- | --- | --- | --- | --- | --- |
| Ciphertext lives | On the host | Nowhere, the host has plaintext | In the repo | In the repo | Inside the provider |
| Key lives | In the repo | No key | On the host, as an env var | KMS, age or PGP | Inside the provider, behind IAM |
| A leak of the host's env var store gives | Ciphertext | Every secret | The private key only | Depends where you keep the key credentials | Nothing, when access is by IAM role |
| A leak of the repo gives | The key only | Nothing | Ciphertext | Ciphertext | Nothing |
| Needed at runtime | Node's built-in `crypto` | Nothing | The dotenvx CLI or library | The `sops` binary and access to the key | Provider SDK, an IAM role, a network call |
| Changing a secret is | A host update | A host update | A commit | A commit | A provider update |
| Setup | One command | None | Encrypt the file, put the private key on the host | Key management and a decrypt step in your deploy | IAM policies and roles |

**Use preseal when:**

- Your secrets sit in a host's env var store today and you want a second factor without new infrastructure.
- Your code runs somewhere it has no IAM role to call a KMS with.
- Your repo is private.

**Use something else when:**

- Your repo is public. The key would be public too.
- You are on AWS or GCP with IAM roles. Envelope encryption with KMS, or a secret manager, keeps the key out of your code entirely and is stronger.
- You want secrets versioned and reviewed with the code. dotenvx and SOPS put the ciphertext in the repo.
- You need an audit log of who read which secret.

## Installation

Run it with no install:

```bash
npx preseal --help
```

Add it to a project as a dev dependency, then call it as `npx preseal` or from a package script:

```bash
npm install --save-dev preseal
pnpm add --save-dev preseal
yarn add --dev preseal
```

Install it globally:

```bash
npm install --global preseal
```

Run it from source. There is nothing to build or install:

```bash
git clone https://github.com/DavidWells/preseal.git
node preseal/bin/preseal.js --help
```

Install it as a regular dependency only if you want the [runtime API](#runtime-api) in your app.

### Requirements

Node 18.3 or newer, and the CLI for each target you use:

| Target | CLI | Login it uses |
| --- | --- | --- |
| Netlify | [Netlify CLI](https://docs.netlify.com/cli/get-started/) | `netlify login`, or `NETLIFY_AUTH_TOKEN` |
| AWS SSM | [AWS CLI](https://docs.aws.amazon.com/cli/) | The AWS credential chain (`--profile`, `--region`) |
| 1Password | [1Password CLI](https://developer.1password.com/docs/cli/get-started) | The `op` sign-in, usually the desktop app with Touch ID |

## Quick start

1. Encrypt your first secret. This creates `src/env-key.js` (`./env-key.js` when there is no `src/` folder).

   ```bash
   npx preseal set STRIPE_SECRET_KEY --to netlify
   ```

2. Read it through the key file in server code.

   ```js
   const { env } = require('./src/env-key')

   const stripe = require('stripe')(env('STRIPE_SECRET_KEY'))
   ```

3. Commit `src/env-key.js` and deploy.

4. Confirm the stored value decrypts with the key you committed.

   ```bash
   npx preseal check STRIPE_SECRET_KEY --to netlify
   ```

5. Move the rest of your secrets.

   ```bash
   npx preseal push .env.production --to netlify --except 'NODE_ENV,*_PUBLIC_*'
   ```

### Converting variables that are already live

Order matters when a running app already reads a variable as plaintext. Encrypt it too early and the app receives the string `enc:v1:...` as its secret.

1. `preseal init`, switch your code from `process.env.NAME` to `env('NAME')`, and deploy. Plaintext passes through `env()`, so nothing changes yet.
2. `preseal reseal NAME --to netlify` to encrypt the stored value in place.
3. Redeploy if your host needs that to pick up changed variables.

## The key file

`preseal init` (or the first `set`, `push`, `reseal` or `encrypt`) writes this:

```js
// src/env-key.js
const crypto = require('crypto')

if (typeof document !== 'undefined') {
  throw new Error('env-key was imported in browser code. It must stay on the server.')
}

const ENV_KEYS = {
  v1: 'A_BASE64_KEY_OF_32_BYTES=',
}

function decrypt(value) { /* 10 lines of AES-256-GCM */ }

const env = (name) => { /* decrypt(process.env[name]), cached per name */ }

module.exports = { env, ENV_KEYS }
```

The file is self-contained: your app needs nothing installed to decrypt. A value is decrypted once, and reading it again is a lookup.

`init` writes one of two flavors:

| Flavor | When | What you get |
| --- | --- | --- |
| Standalone (default) | `preseal` is not in your `dependencies`, or you pass `--standalone` | The file above. `env(name)` only. |
| Linked | The package is in your `dependencies`, or you pass `--linked` | A shorter file that imports `createEnv`, which adds a fallback argument, `env.required()`, `env.all()` and `env.inject()`. |

It also matches your module system: TypeScript when there is a `tsconfig.json`, ESM when `package.json` has `"type": "module"`, otherwise CommonJS.

| `init` option | What it does |
| --- | --- |
| `--file <path>` | Where to write the key file. A custom location is recorded in `package.json` so later commands find it. |
| `--format cjs\|esm\|ts` | Module flavor. Default: detected. |
| `--standalone`, `--linked` | Force a flavor. |
| `--print` | Print the module to stdout and write nothing. |
| `--force` | Overwrite an existing key file. Every value encrypted with the old key stops decrypting. Use `rotate` instead unless you mean it. |

## Targets: where the ciphertext goes

Pass `--to` once per target. Each target gets the same ciphertext.

```bash
preseal set STRIPE_SECRET_KEY --to netlify --to op://Engineering/my-app
```

| Target | Stores the value as | Options |
| --- | --- | --- |
| `netlify` | An env var on the linked site | `--context`, `--scope`, `--secret`, `--site`, `--filter` |
| `netlify:<site>` | An env var on a site, by name or ID | same |
| `ssm:/my-app/prod` | SSM parameter `/my-app/prod/<NAME>` | `--region`, `--profile`, `--ssm-type`, `--kms-key-id`, `--tier` |
| `ssm:/my-app/{name}/prod` | SSM parameter, with the name placed where `{name}` is | same |
| `op://Vault/Item` | A field named `<NAME>` on a 1Password item | |
| `op://Vault/Item/Section` | A field in a section of the item | |
| `dotenv:.env.production` | A line in a dotenv file | |
| `stdout` (default for `set`) | Prints `NAME=enc:v1:...`, ready to paste into any host | |

### Netlify

```bash
preseal set STRIPE_SECRET_KEY --to netlify --context production,deploy-preview
preseal set STRIPE_SECRET_KEY --to netlify:my-site --scope functions
```

- `--context` and `--scope` take several values with commas or by repeating the flag. The Netlify CLI's space-separated form is rejected, because the second word would be read as a variable name.
- `check` and `reseal` read one context: `dev` unless you pass `--context`, or the first one when you pass several. Their output names the context they read.
- `--secret` marks the variable as a Netlify secret and needs a non-dev `--context`. Netlify masks a secret when it is read, so `check` and `reseal` refuse it with an error.
- Netlify rejects `--context` and `--scope` together when the variable already exists. Set them in two runs.

### AWS SSM

```bash
preseal set DATABASE_URL --to ssm:/my-app/prod --region us-east-1 --profile prod
```

Parameters are written as `SecureString` with `--overwrite`. Pass `--ssm-type String` for a plain parameter and `--kms-key-id` for your own KMS key. Ciphertext is about a third longer than the plaintext, and a Standard parameter holds 4 KB, so values over roughly 3,000 bytes need `--tier Advanced`.

### 1Password

```bash
preseal push .env.production --to op://Engineering/my-app
```

Each variable is a concealed field on the item. An item that doesn't exist yet is created as a Secure Note. This suits setups that load env vars from 1Password at deploy time, and it makes a second copy of the ciphertext. `check` and `reseal` read the item with plain `op read`, never a cache, so they always see what is stored now.

### Batching

Every external call is a CLI process that takes a few hundred milliseconds or more, so commands batch them:

| Target | Reading many (`check`, `reseal`) | Writing many (`set`, `push`, `reseal`) |
| --- | --- | --- |
| Netlify | One `env:list` | Four `env:set` at a time |
| AWS SSM | One `get-parameters` per ten names | Four `put-parameter` at a time |
| 1Password | One `op item get` (one Touch ID prompt) | One `op item edit` (one Touch ID prompt) |

Measured from a laptop against the real services:

| | `check` | `push` |
| --- | --- | --- |
| 20 Netlify variables | 1.5 s | 11 s |
| 40 SSM parameters | 1.0 s | 8 s |

A 1Password `push` of 20 fields is one `op item edit`, or two calls when the item has to be created first. A `check` of 20 fields is one `op item get`.

Results are always reported in the order you gave the names. If a write fails partway through, values after the failed one may already be stored on Netlify or SSM, while a 1Password edit stores all of its fields or none. Run the command again. It is safe to repeat.

## Sources: where the plaintext comes from

With no flags, `set` shows a hidden prompt, or reads stdin when something is piped in.

```bash
pbpaste | preseal set STRIPE_SECRET_KEY --to netlify
```

Better, pull the value from where it already lives:

```bash
preseal set STRIPE_SECRET_KEY --from op://Engineering/Stripe/secret-key --to netlify
preseal set DATABASE_URL --from ssm:/legacy/prod/DATABASE_URL --to netlify
```

| Source | Reads from |
| --- | --- |
| `op://Vault/Item/field` | 1Password. Uses [`op-stash`](https://www.npmjs.com/package/@davidwells/op-stash) when it is installed, otherwise `op read`. |
| `ssm:/path/to/param` | AWS SSM, decrypted. Honors `--region` and `--profile`. |
| `env:NAME` | An environment variable of the current shell |
| `file:path` | A file. One trailing newline is dropped. |

Set several variables at once by giving each its own source:

```bash
preseal set STRIPE_SECRET_KEY=op://Eng/Stripe/secret DATABASE_URL=op://Eng/DB/url --to netlify
```

`NAME=literal` and `--value` also work. Both put the secret in your shell history.

## Commands

Status lines (`✔ NAME → ...`) go to stderr. Values go to stdout, so `preseal encrypt > file` and pipes stay clean. Every command exits 0 on success and 1 on any failure.

### `preseal init`

Create the key file with a new `v1` key. Options are listed under [The key file](#the-key-file).

```bash
preseal init                               # src/env-key.js, flavor detected
preseal init --file config/secrets-key.ts  # custom location, recorded in package.json
preseal init --print --format esm          # look before you write
```

### `preseal set <NAME...> --to <target>`

Encrypt one or more values and store the ciphertext. Creates the key file when there isn't one.

```bash
preseal set STRIPE_SECRET_KEY --to netlify                    # hidden prompt
preseal set STRIPE_SECRET_KEY                                 # print NAME=enc:v1:... instead
preseal set A_KEY B_KEY --to netlify                          # one hidden prompt per name
preseal set A_KEY=op://Eng/A/key B_KEY=file:./b.txt --to ssm:/my-app/prod
preseal set STRIPE_SECRET_KEY --to netlify --dry-run          # show the plan, store nothing
```

### `preseal push <file> --to <target>`

Encrypt every value in a dotenv file and store the ciphertext.

```bash
preseal push .env.production --to netlify --context production
preseal push .env.production --to netlify --only 'STRIPE_*,DATABASE_URL'
preseal push .env.production --to netlify --except 'NODE_ENV,*_PUBLIC_*'
```

`--only` and `--except` take comma-separated names, with `*` as a wildcard. Values that are already encrypted are stored as they are. Empty values are skipped and listed.

### `preseal reseal <NAME...> --to <target>`

Read a value back from a target, encrypt it with the newest key, and write it back. Use it to convert a plaintext variable that is already on your host, and to finish a key rotation.

```bash
preseal reseal STRIPE_SECRET_KEY --to netlify --context production
preseal reseal STRIPE_SECRET_KEY DATABASE_URL --to ssm:/my-app/prod --dry-run
preseal reseal STRIPE_SECRET_KEY --to netlify --force   # new ciphertext even if already on the newest key
```

A value already encrypted with the newest key is left alone and reported as `already encrypted with v2`. A name that is not set stops the run with an error, after the names before it are written.

### `preseal check <NAME...> --to <target>`

Confirm that stored values decrypt with the key in your repo. Prints the key version and never the value.

```bash
preseal check STRIPE_SECRET_KEY DATABASE_URL --to netlify --context production
```

```
✔ STRIPE_SECRET_KEY in Netlify (linked site, context production): decrypts with key v2
✖ DATABASE_URL in Netlify (linked site, context production): is stored as plaintext
```

Exits 1 when any value is missing, stored as plaintext, or encrypted with a key you don't have. Run it in CI before a deploy.

### `preseal rotate`

Add the next key version to the key file. New values are encrypted with it, and old keys stay so existing values keep decrypting.

```bash
preseal rotate
```

1. `preseal rotate`, then deploy so the running app knows the new key.
2. `preseal reseal <NAME...> --to <target>` for each stored value.
3. Delete the old key line from the key file and deploy again.

### `preseal encrypt`, `decrypt`, `keygen`

One-off helpers that touch no target.

```bash
pbpaste | preseal encrypt          # ciphertext for one value
preseal encrypt --from op://Eng/Stripe/secret
preseal decrypt 'enc:v1:...'       # plaintext, to stdout
preseal keygen                     # a new base64 key
```

### Options

| Option | Commands | What it does |
| --- | --- | --- |
| `-t, --to <target>` | `set`, `push`, `reseal`, `check` | Where the ciphertext goes. Repeatable. |
| `-f, --from <source>` | `set`, `encrypt`, `decrypt` | Where the value comes from |
| `--value <text>` | `set`, `encrypt`, `decrypt` | A literal value. It lands in your shell history. |
| `-k, --key-file <path>` | all | The key file to use |
| `--cwd <dir>` | all | The project directory, which must exist. The key file, `package.json` and relative file paths are looked up there, and the `netlify`, `aws` and `op` CLIs run there, so `--to netlify` means the site linked in that directory. Default: the current directory. |
| `--dry-run` | `set`, `push`, `reseal`, `init`, `rotate` | Report what would be written and write nothing: no target, no key file, no `package.json`. When there is no key file yet, the first line is `would create src/env-key.js with a new key (v1)` and the plan is worked out with a key that is thrown away. |
| `--force` | `init`, `reseal` | `init`: overwrite the key file. `reseal`: re-encrypt values that are already on the newest key. |
| `--only`, `--except` | `push` | Filter names, comma-separated, `*` wildcard |
| `-c, --context`, `-s, --scope`, `--secret`, `--site`, `--filter` | Netlify targets | Passed to the Netlify CLI |
| `--region`, `--profile` | SSM targets and `ssm:` sources | Passed to the AWS CLI |
| `--ssm-type`, `--kms-key-id`, `--tier` | SSM targets | Parameter type, KMS key and tier |
| `-h, --help`, `-v, --version` | | |

## Configuration

There is no config file to write. The CLI looks for the key file in this order:

1. `--key-file <path>`
2. `"preseal": { "keyFile" }` in `package.json`
3. `src/env-key.js`, `.cjs`, `.mjs` or `.ts`
4. `./env-key.js`, `.cjs`, `.mjs` or `.ts`
5. The `PRESEAL_KEY` environment variable

`init --file` writes the `package.json` entry for you when the location is not one of the defaults:

```json
{
  "name": "my-app",
  "preseal": {
    "keyFile": "config/secrets-key.ts"
  }
}
```

| Environment variable | Read by | What it does |
| --- | --- | --- |
| `PRESEAL_KEY` | preseal | A base64 key used as `v1` when no key file is found. For one-off `encrypt` and `decrypt` outside a project. |
| `NETLIFY_AUTH_TOKEN` | Netlify CLI | Authenticates without `netlify login`, for CI |
| `AWS_PROFILE`, `AWS_REGION` and the rest of the credential chain | AWS CLI | Selects the account and region |

The CLI reads the keys out of the key file as text. It never executes the file, so it works the same for CommonJS, ESM and TypeScript.

## Runtime API

Install the package as a regular dependency to use these in your app.

```js
const { createEnv, encrypt, decrypt, isEncrypted, generateKey } = require('preseal')

const env = createEnv({ v1: 'base64 key' })

env('STRIPE_SECRET_KEY')              // decrypted value, or undefined
env('PORT', '3000')                   // fallback when unset or empty
env.required('STRIPE_SECRET_KEY')     // throws when unset
env.all()                             // { NAME: plaintext } for every encrypted variable
env.inject()                          // decrypt process.env in place
```

| Function | What it does |
| --- | --- |
| `createEnv(keys, { source })` | Returns `env`. `keys` is one base64 key or `{ v1, v2 }`. `source` defaults to `process.env`. |
| `env(name, fallback)` | The decrypted value. Plaintext passes through. Decrypted values are cached per name. |
| `env.required(name)` | Same, and throws `preseal: NAME is not set` when unset or empty |
| `env.all(names)` | An object of decrypted values. Default: every encrypted variable. |
| `env.inject(target)` | Replaces encrypted values in place and returns the names it decrypted. A bad value leaves the target untouched. |
| `encrypt(plaintext, keys, { version })` | Returns `enc:vN:...`. Default version: the newest key. |
| `decrypt(value, keys)` | Returns the plaintext. Values without the prefix are returned as they are. |
| `isEncrypted(value)`, `versionOf(value)` | Test for the prefix, read the key version |
| `generateKey()`, `latestVersion(keys)` | A new base64 key, the newest version in a key map |

`env.inject()` is for libraries that read `process.env` themselves. Call it once at startup. Child processes you spawn afterwards inherit the plaintext.

Errors name the variable and never include its value. A tampered value throws instead of returning garbage, because GCM is authenticated.

TypeScript declarations are included for the package and for its `/seal` and `/adapters` entry points.

### Sealing from code

```js
const { seal } = require('preseal/seal')

const { version, sealed, written } = await seal({
  values: { STRIPE_SECRET_KEY: 'sk_live_...' },
  keys: { v1: 'base64 key' },
  targets: ['netlify', 'ssm:/my-app/prod'],
  targetOptions: { context: ['production'], region: 'us-east-1' },
  dryRun: false,
  onWrite: (event) => console.log(event.name, '→', event.label)
})
```

### Custom adapters

A target is any object with a `set` function. Add `get` to support reading the value back.

```js
await seal({
  values,
  keys,
  targets: [{
    name: 'vault',
    async set(name, value) { /* store the ciphertext */ },
    async get(name) { /* return it */ }
  }]
})
```

Three optional members make a slow store faster: `getMany(names)` reads many names in one call and returns `[{ value }, { error }, ...]` in the same order, `setMany(entries)` writes many `[name, value]` pairs in one call, and `concurrency` says how many `set` calls may run at once.

The built-in adapters are exported from `preseal/adapters`: `createNetlifyAdapter`, `createSsmAdapter`, `createOnePasswordAdapter`, `createDotenvAdapter`, `createStdoutAdapter` and `resolveTarget`.

## Use it with an AI agent

The repo ships an agent skill in [`skill/SKILL.md`](skill/SKILL.md). It teaches a coding agent the commands, the order to do things in, and the rules that keep plaintext out of command lines and chat: read values with `--from`, run `--dry-run` first, verify with `check` and never `decrypt`.

For Claude Code, copy it into your skills folder:

```bash
mkdir -p ~/.claude/skills/preseal && cp node_modules/preseal/skill/SKILL.md ~/.claude/skills/preseal/
```

Without a local install, take the file from the repo:

```bash
git clone https://github.com/DavidWells/preseal.git && mkdir -p ~/.claude/skills/preseal && cp preseal/skill/SKILL.md ~/.claude/skills/preseal/
```

Other agents can read the same file: point them at `node_modules/preseal/skill/SKILL.md`.

## Value format

```
enc:<version>:base64( iv[12 bytes] || authTag[16 bytes] || ciphertext )
```

AES-256-GCM with a 32-byte key and a random IV per value. The version names the key that encrypted the value, which is what lets two keys be live during a rotation. Encrypting the same value twice gives different ciphertext.

## What this protects against, and what it doesn't

It helps when the host's env var store, admin tooling or logs leak and the attacker does not have your code. It also covers a teammate screenshotting the settings page.

It does not help when:

- **The attacker has your repo and the host's store.** The key is as sensitive as your source. A public repo makes this useless.
- **The attacker owns the whole platform.** If your host builds from your repo, the key is in the build output too. That usually has different access from the env var store, but it is the same company.
- **The key ships to the browser.** Import the key file from server code only. The generated file throws if it loads where `document` exists.
- **The attacker is inside your running process.** The plaintext is in memory there, as it is with any scheme.

It is a speed bump, not a vault: one point of failure becomes two.

## Troubleshooting

### `✖ NAME in Netlify (linked site, context dev): is not set`

The variable exists, but only in another context. `check` and `reseal` read `dev` unless told otherwise.

```bash
preseal check NAME --to netlify --context production
```

### `no Netlify site is linked in this folder`

Link the folder, or name the site.

```bash
netlify link
preseal set NAME --to netlify:my-site
```

### `"deploy-preview" looks like a --context or --scope value, not a variable name`

You used the Netlify CLI's space-separated form. Use commas or repeat the flag.

```bash
preseal set NAME --to netlify --context production,deploy-preview
```

### `NAME is a Netlify secret. Netlify masks its value`

A Netlify secret cannot be read back, so it cannot be checked or resealed. To change it or move it to a new key, set it again from the original plaintext.

```bash
preseal set NAME --from op://Vault/Item/field --to netlify --context production --secret
```

### `could not decrypt (wrong v1 key, or the value was changed)`

The stored value was encrypted with a different key from the one in your repo. Usually the key file was regenerated with `init --force`, or the value came from another project. Set the value again from the plaintext.

A standalone key file reports the same problem at runtime as a raw Node `crypto` error, such as `bad decrypt` or `Unsupported state or unable to authenticate data`, depending on the Node version.

### `no key for enc:v2 values. Known key versions: v1`

The value was encrypted with a newer key than the code has. Pull the latest key file, or deploy it, before the resealed values go live. This is why `rotate` says to deploy before you `reseal`.

### `no key file found. Run preseal init first`

`check`, `decrypt` and `rotate` never create a key, and neither does `encrypt --dry-run`. Run from the folder that has the key file, or point at it.

```bash
preseal check NAME --to netlify --key-file ./apps/api/src/env-key.js
```

In a monorepo, `--cwd` does both jobs: it finds the key file in that folder and runs the `netlify` CLI there, so the site linked in that folder is the one checked.

```bash
preseal check NAME --to netlify --cwd ./apps/api
```

### `--cwd ./apps/typo is not a directory`

`--cwd` has to name a folder that exists. preseal does not create it, because the `netlify`, `aws` and `op` CLIs run inside it.

### `src/env-key.js already exists`

`init` will not replace a key file, because every stored value would stop decrypting. To add a key, run `preseal rotate`.

### `` `netlify` was not found on your PATH ``

The target's CLI is not installed. The message includes the install link for `netlify`, `aws` or `op`.

### `` `aws ssm` failed (exit 254) `` and other CLI failures

Any other failure is passed through with the last lines of the CLI's own output. It is nearly always an expired login. Fix it in that CLI (`aws sso login`, `netlify login`, `op signin`) and run the command again.

### `one value was given for several names`

One `--from`, `--value` or piped value cannot fill several variables. Give each its own source.

```bash
preseal set A=op://Eng/A/key B=op://Eng/B/key --to netlify
```

### `env-key was imported in browser code`

A client bundle imported the key file. Import it only from server code: functions, API routes, server components, build scripts.

## Limitations

- **A speed bump, not a vault.** See [what it protects against](#what-this-protects-against-and-what-it-doesnt). With IAM available, KMS is stronger.
- **Losing the key file loses the values.** Ciphertext cannot be recovered without it. Keep the plaintext somewhere you can set it again from, which is what `--from op://...` is for.
- **Netlify secrets are write-only.** `check` and `reseal` cannot read them.
- **`check` and `reseal` read one Netlify context per run.** Run them once per context you care about.
- **No delete or list command.** Remove a variable with the host's own tools.
- **Writes are not transactional on Netlify and SSM.** A failed `push` can leave some values stored. Rerun it.
- **Writes are as fast as the CLIs.** A Netlify `env:set` takes over a second, so 20 variables take about 11 s even four at a time.
- **1Password has no account option.** The `op` CLI's default account is used.
- **`push` does not expand variables.** `${OTHER}` in a dotenv file is encrypted as written.
- **Custom adapters are code-only.** The CLI takes the built-in targets.
- **Node only.** The key file needs Node's `crypto` and `Buffer`. Edge runtimes are untested.
- **The TypeScript key file imports `crypto` as a default import**, which needs `esModuleInterop` or `allowSyntheticDefaultImports` in `tsconfig.json`.
- **Tested on macOS with Node 26.** Node 18.3 is the declared minimum and Windows is untested. The `--filter`, `--kms-key-id` and `--tier` options are passed through but have not been exercised against the real services.

## FAQ

### Isn't committing a key to the repo a bad idea?

Committing a key that unlocks something on its own is. This key unlocks nothing without the ciphertext, and the ciphertext is on your host, not in the repo. Compared with plaintext env vars, a repo leak gives an attacker nothing they can use by itself, and a host leak now gives them nothing either.

### What if my repo is public?

Don't use this. The key would be public.

### Does my app need this package installed?

No. The default key file is self-contained and uses only Node's `crypto`. You need the package in `dependencies` only for the linked flavor or the runtime API.

### Do local `.env` files still work?

Yes. A value without the `enc:` prefix is returned as it is, so local development, tests and plain config need no changes.

### How do I change a secret's value?

Run `set` again with the new value. It overwrites the stored one.

### What happens if I lose the key file?

The stored values cannot be decrypted. Run `init` and `set` them again from the original plaintext.

### Can I use it in CI?

Yes. The key file is in the checkout, so `preseal check NAME --to netlify` works once the target's CLI can log in (`NETLIFY_AUTH_TOKEN`, or the AWS credential chain). It exits 1 when a value would not decrypt.

### My host isn't Netlify, SSM or 1Password. Can I use it?

Yes. `preseal set NAME` prints `NAME=enc:v1:...` to paste into any dashboard, and `--to dotenv:.env.production` writes a file of ciphertext to upload. From code, pass a [custom adapter](#custom-adapters).

### Is it compatible with the hand-rolled version from the blog post?

Yes. The value format is identical, so values encrypted by either decrypt with the other, given the same key.

### Why does a 1Password command ask for Touch ID?

Each `op` process needs approval. preseal batches a whole `push`, `check` or `reseal` into one `op` call, so you are asked once per command.

## License

MIT
