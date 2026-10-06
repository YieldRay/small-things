#!/usr/bin/env -S node --experimental-strip-types --disable-warning=ExperimentalWarning
import { parseArgs, styleText } from "node:util";
import { writeFile } from "node:fs/promises";
import process from "node:process";
import pkg from "../../package.json" with { type: "json" };
import {
  Favicons,
  Fonts,
  Library,
  Screenshots,
  Secrets,
  solvePow,
  powLevel,
} from "./index.ts";

// https://nodejs.org/api/util.html#utilparseargsconfig
const { values, positionals } = parseArgs({
  options: {
    help: { type: "boolean", multiple: false, short: "h", default: false },
    url: { type: "string" },
    out: { type: "string", short: "o" },
    category: { type: "string" },
    subset: { type: "string" },
    limit: { type: "string" },
    offset: { type: "string" },
    width: { type: "string" },
    height: { type: "string" },
    scale: { type: "string" },
    scheme: { type: "string" },
    ttl: { type: "string" },
    wait: { type: "string" },
    hours: { type: "string" },
    burn: { type: "boolean", default: false },
    id: { type: "string" },
  },
  strict: true,
  allowPositionals: true,
});

const service = positionals[0];

if (values.help || service === "help" || service === undefined) help(service === undefined ? 1 : 0);

const base = { url: values.url };

try {
  switch (service) {
    case "icon": {
      const target = need(positionals[1], "url");
      const icon = await new Favicons(base).get(target);
      if (icon === null) {
        process.stderr.write("no favicon\n");
        process.exit(1);
      }
      await emit(icon.bytes, `${icon.contentType}\n`);
      break;
    }
    case "fonts": {
      const result = await new Fonts(base).search({
        q: positionals[1],
        category: values.category,
        subset: values.subset,
        limit: numberOption(values.limit),
        offset: numberOption(values.offset),
      });
      for (const family of result.families) {
        process.stdout.write(`${family.slug}\t${family.name}\t${family.category}\n`);
      }
      process.stderr.write(`${result.count} of ${result.total} families\n`);
      break;
    }
    case "font": {
      const slug = need(positionals[1], "slug");
      const fonts = new Fonts(base);
      if (positionals[2] === undefined) {
        process.stdout.write(`${JSON.stringify(await fonts.family(slug), null, 2)}\n`);
      } else {
        await emit(await fonts.download(slug, positionals[2]), `saved ${positionals[2]}\n`);
      }
      break;
    }
    case "pow": {
      const action = need(positionals[1], "action");
      if (action === "solve") {
        const level = Number.parseInt(need(positionals[2], "level"), 10);
        const doc = positionals[3] ?? (await readStdinText()).trim();
        process.stderr.write(`solving level ${level}…\n`);
        process.stdout.write(`${solvePow(doc, level)}\n`);
      } else if (action === "level") {
        process.stdout.write(`${powLevel(need(positionals[2], "token"))}\n`);
      } else {
        process.stderr.write(`Unknown pow action ${action}\n`);
        help(1);
      }
      break;
    }
    case "shot": {
      const target = need(positionals[1], "url");
      process.stderr.write("solving proof of work…\n");
      const shot = await new Screenshots(base).capture({
        url: target,
        width: numberOption(values.width),
        height: numberOption(values.height),
        scale: numberOption(values.scale),
        scheme: values.scheme as "light" | "dark" | undefined,
      });
      await emit(shot.bytes, `captured ${target}${shot.cached ? " (cache hit)" : ""}\n`);
      break;
    }
    case "lib": {
      const action = need(positionals[1], "action");
      if (action === "register") {
        const lib = new Library({ ...base, id: values.id });
        const state = await lib.register(Number.parseInt(need(positionals[2], "count"), 10));
        process.stdout.write(`${JSON.stringify(state, null, 2)}\n`);
        break;
      }
      const lib = new Library({ ...base, id: need(positionals[2], "pool id") });
      if (action === "inspect") {
        process.stdout.write(`${JSON.stringify(await lib.inspect(), null, 2)}\n`);
      } else if (action === "borrow") {
        const lease = await lib.borrow({ ttl: numberOption(values.ttl), wait: numberOption(values.wait) });
        if (lease === null) {
          process.stderr.write("no resource available\n");
          process.exit(1);
        }
        process.stdout.write(`${JSON.stringify(lease, null, 2)}\n`);
      } else if (action === "return") {
        const returned = await lib.returnLease(need(positionals[3], "lease id"));
        process.stderr.write(returned ? "returned\n" : "lease unknown or already freed\n");
        if (!returned) process.exit(1);
      } else if (action === "delete") {
        await lib.delete();
        process.stderr.write("deleted\n");
      } else {
        process.stderr.write(`Unknown lib action ${action}\n`);
        help(1);
      }
      break;
    }
    case "secret": {
      const action = need(positionals[1], "action");
      const secrets = new Secrets(base);
      if (action === "create") {
        const text = positionals[2] ?? (await readStdinText());
        const created = await secrets.create(text, {
          expiresHours: numberOption(values.hours),
          autoDestroy: values.burn,
        });
        process.stdout.write(`${created.url}\n`);
      } else if (action === "open") {
        const plaintext = await secrets.open(need(positionals[2], "url"));
        process.stderr.write("\n");
        process.stdout.write(plaintext);
        process.stderr.write("\n");
      } else if (action === "burn") {
        await secrets.burn(need(positionals[2], "id"));
        process.stderr.write("burned\n");
      } else {
        process.stderr.write(`Unknown secret action ${action}\n`);
        help(1);
      }
      break;
    }
    default:
      process.stderr.write(`Unknown service ${service}\n`);
      help(1);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

/** Write bytes to --out or stdout, with a note on stderr. */
async function emit(bytes: Uint8Array, note: string): Promise<void> {
  if (values.out !== undefined) {
    await writeFile(values.out, bytes);
    process.stderr.write(`wrote ${values.out}\n`);
  } else {
    process.stderr.write(note);
    process.stdout.write(bytes);
  }
}

async function readStdinText(): Promise<string> {
  if (process.stdin.isTTY) {
    process.stderr.write("pass the input as an argument or pipe it on stdin\n");
    help(1);
  }
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  return text;
}

function numberOption(value: string | undefined): number | undefined {
  return value === undefined ? undefined : Number.parseFloat(value);
}

function need(value: string | undefined, name: string): string {
  if (value === undefined) {
    process.stderr.write(`missing ${name}\n`);
    help(1);
  }
  return value;
}

function help(code: number): never {
  const out = code === 0 ? process.stdout : process.stderr;
  out.write(`${styleText("green", "ccme")} v${pkg.version}

  Client for cc.me — favicons, fonts, semaphores, proof of work, screenshots, secrets

  ${styleText("bold", "Usage:")}

  ccme icon <url> [-o file]                    Fetch a site's favicon
  ccme fonts [query] [--category C] [--limit N]  Search the Google Fonts catalog
  ccme font <slug> [filename] [-o file]        Family details, or download a font file
  ccme pow solve <level> [doc]                 Solve a proof of work (doc or stdin)
  ccme pow level <token>                       Print the level a token proves
  ccme shot <url> [-o file] [--width --height --scale --scheme]
  ccme lib register <count> [--id uuid]        Register a semaphore pool, prints its UUID
  ccme lib inspect <id>
  ccme lib borrow <id> [--ttl S] [--wait S]
  ccme lib return <id> <lease>
  ccme lib delete <id>
  ccme secret create [text] [--hours N] [--burn]   Share a secret (text or stdin)
  ccme secret open <url>                       Read and decrypt a shared secret
  ccme secret burn <id>

  ${styleText("bold", "Options:")}

  --url <url>                                  Service endpoint (default https://cc.me/)
  -o, --out <file>                             Write binary output to a file
  -h, --help                                   Show this help
`);
  process.exit(code);
}
