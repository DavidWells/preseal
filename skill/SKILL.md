---
name: preseal
description: Encrypt env vars before the host sees them with the preseal CLI, so Netlify, AWS SSM or 1Password store only `enc:v1:...` ciphertext and the app decrypts at runtime with a key file in the repo. Use when asked to encrypt, seal or move secrets or env vars to Netlify, AWS SSM Parameter Store, 1Password or a dotenv file, to convert plaintext env vars that are already live, to rotate the encryption key, to check that stored values decrypt, or when a project has an `env-key.js` file, `enc:v1:` values or a `preseal` dependency.
---

# preseal: the host stores ciphertext, the repo holds the key

`preseal` encrypts a value on this machine and stores `NAME=enc:v1:...` on the host. The decryption
key lives in a source file in the repo (`src/env-key.js`), and the app reads secrets through that
file. A leak of the host's env var store alone gives an attacker nothing.

It is a speed bump, not a vault. It does not help when the attacker also has the repo, or can run
code inside the app. Say so if the user expects more. Background:
https://davidwells.io/blog/encrypt-env-vars-before-your-host-sees-them

Run it with `npx preseal <command>`, or `preseal <command>` when it is installed. It needs Node 18.3
or newer and the CLI of each target used: `netlify`, `aws` or `op`.

## 1. Rules for agents

- **Never put a plaintext secret in a command line, a file you write, or the chat.** Do not use
  `--value` or `NAME=literal`: both put the secret in argv and shell history.
- **Read the value from where it already lives** with `--from` (section 3). If it lives nowhere yet,
  ask the user to run the `set` command in their own terminal. There it shows a hidden prompt.
- **An agent shell has no TTY.** `set` with no `--from` reads stdin there and never prompts, so a
  bare `preseal set NAME --to netlify` fails with `NAME has no value to encrypt`.
- **Do not run `preseal decrypt`** unless the user asks to see a value. It prints plaintext. To
  confirm a value is good, use `check`, which prints only whether it decrypts.
- **Never print, paste or log the key** from the key file. Refer to it by key version (`v1`).
- **Run with `--dry-run` first** for `push`, `reseal` and anything that touches production. A dry
  run writes nothing: no target, no key file.
- **Never run `init --force`.** It replaces the key, and every stored value stops decrypting. Use
  `rotate`.
- Writing to a host is outward-facing. Confirm the target (site, context, SSM path, region,
  1Password item) with the user before the first real write.

## 2. Commands

| Task | Command |
|---|---|
| Create the key file | `preseal init` |
| Encrypt one value and store it | `preseal set NAME --from <source> --to <target>` |
| Encrypt a whole dotenv file | `preseal push .env.production --to <target>` |
| Encrypt a value already stored on the host, in place | `preseal reseal NAME --to <target>` |
| Confirm stored values decrypt with the committed key | `preseal check NAME --to <target>` |
| Add a new key version | `preseal rotate` |
| Print ciphertext for one value | `preseal encrypt --from <source>` |

`set`, `push`, `reseal` and `encrypt` create the key file when there is none. `check`, `decrypt` and
`rotate` never do. Status lines go to stderr and values go to stdout. Exit code 0 means success;
`check` exits 1 when any name fails.

## 3. Sources and targets

| `--from` source | Reads from |
|---|---|
| `op://Vault/Item/field` | 1Password (`op-stash` when installed, otherwise `op read`) |
| `ssm:/path/to/param` | AWS SSM, decrypted (`--region`, `--profile`) |
| `env:NAME` | An environment variable of the current shell |
| `file:path` | A file |

| `--to` target | Stores the value as | Options |
|---|---|---|
| `netlify` | Env var on the linked site | `--context`, `--scope`, `--secret`, `--site`, `--filter` |
| `netlify:<site>` | Env var on a site by name or ID | same |
| `ssm:/my-app/prod` | SSM parameter `/my-app/prod/<NAME>` | `--region`, `--profile`, `--ssm-type`, `--kms-key-id`, `--tier` |
| `op://Vault/Item` | Field `<NAME>` on a 1Password item | |
| `dotenv:.env.production` | A line in a dotenv file | |
| `stdout` (default for `set`) | Prints `NAME=enc:v1:...` | |

Repeat `--to` to store the same ciphertext in several places. Give several variables their own
sources in one run:

```bash
preseal set STRIPE_SECRET_KEY=op://Eng/Stripe/secret DATABASE_URL=op://Eng/DB/url --to netlify
```

Netlify details that trip people up:

- `--context production,deploy-preview` uses commas or a repeated flag. The Netlify CLI's
  space-separated form is rejected.
- `check` and `reseal` read one context: `dev` unless `--context` is passed.
- A variable stored with `--secret` reads back masked, so `check` and `reseal` refuse it.

In a monorepo, pass `--cwd ./apps/api`. The key file is looked up there and the `netlify`, `aws` and
`op` CLIs run there, so `--to netlify` means the site linked in that folder.

## 4. Workflows

### New secret

```bash
preseal set STRIPE_SECRET_KEY --from op://Engineering/Stripe/secret-key --to netlify --context production
```

Then, in server code, read it through the key file, commit the key file, deploy, and check:

```js
const { env } = require('./src/env-key')
const stripe = require('stripe')(env('STRIPE_SECRET_KEY'))
```

```bash
preseal check STRIPE_SECRET_KEY --to netlify --context production
```

`init` matches the project: TypeScript when there is a `tsconfig.json`, ESM when `package.json` has
`"type": "module"`, otherwise CommonJS. Import style follows.

### A whole dotenv file

```bash
preseal push .env.production --to netlify --except 'NODE_ENV,*_PUBLIC_*' --dry-run
```

Leave public values (`*_PUBLIC_*`, `NODE_ENV`) out with `--except`, or pick names with `--only`.
Run it again without `--dry-run` once the plan looks right.

### Variables that are already live as plaintext

Order matters. Encrypt too early and the running app receives the string `enc:v1:...` as its secret.

1. `preseal init`, change the code from `process.env.NAME` to `env('NAME')`, and deploy. Plaintext
   passes through `env()`, so nothing changes yet.
2. Encrypt the stored value in place:

   ```bash
   preseal reseal STRIPE_SECRET_KEY --to netlify --context production
   ```

3. Redeploy if the host needs that to pick up changed variables.

### Rotate the key

1. `preseal rotate` adds `v2` to the key file. Old keys stay, so existing values still decrypt.
2. Commit and deploy, so the running app knows `v2`.
3. `preseal reseal NAME... --to <target>` re-encrypts stored values with `v2`.
4. Delete the `v1` line from the key file and deploy again.

Never reseal before step 2 is live: the app would get values it has no key for.

## 5. In application code

- Import the key file from server code only. The generated file throws if it loads in a browser.
- `env('NAME')` returns the decrypted value, and returns plaintext values unchanged, so a local
  `.env` with plain values keeps working.
- With `preseal` in `dependencies`, the key file is the linked flavor and `env` also has
  `env('PORT', '3000')`, `env.required('NAME')`, `env.all()` and `env.inject()` (decrypts
  `process.env` in place, for libraries that read it themselves).
- To seal from a script, use `seal({ values, keys, targets })` from `preseal/seal`.

## 6. When something fails

| Message | Cause and fix |
|---|---|
| `NAME has no value to encrypt` | No TTY and nothing on stdin. Pass `--from`, or have the user run it |
| `no key file found` | `check`, `decrypt` and `rotate` do not create one. Run from the project folder, or pass `--cwd` or `--key-file` |
| `could not decrypt (wrong v1 key, or the value was changed)` | The stored value was encrypted with a different key file. Check you are in the right project |
| `no key for enc:v2 values` | The code has an older key file than the value. Pull or deploy the key file first |
| `is not set` on `check` | Wrong context, site or path. Netlify reads `dev` unless `--context` is passed |
| `is a Netlify secret. Netlify masks its value` | Stored with `--secret`. It cannot be read back, so set it again from the source |
| `` `netlify` was not found on your PATH `` | Install and log in to that target's CLI |
| `one value was given for several names` | Use `NAME=<source>` pairs, or `push` a file |

For anything else, `preseal --help` lists every flag.
