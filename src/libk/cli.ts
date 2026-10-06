#!/usr/bin/env -S node --experimental-strip-types --disable-warning=ExperimentalWarning
import { parseArgs, styleText } from "node:util";
import process from "node:process";
import pkg from "../../package.json" with { type: "json" };
import { Libk } from "./index.ts";

// https://nodejs.org/api/util.html#utilparseargsconfig
const { values, positionals } = parseArgs({
  options: {
    help: {
      type: "boolean",
      multiple: false,
      short: "h",
      default: false,
    },
    url: {
      type: "string",
    },
    "new-password": {
      type: "string",
    },
  },
  strict: true,
  allowPositionals: true,
});

const command = positionals[0];

if (values.help || command === "help") help(0);
if (command === undefined) help(1);

try {
  switch (command) {
    case "get": {
      const libk = new Libk({ url: values.url, subdomain: need(positionals[1], "subdomain"), password: need(positionals[2], "password") });
      const ips = await libk.get();
      if (ips === null) {
        process.stderr.write("no record\n");
        process.exit(1);
      }
      process.stdout.write(`${ips.join("\n")}\n`);
      break;
    }
    case "update": {
      const libk = new Libk({ url: values.url, subdomain: need(positionals[1], "subdomain"), password: need(positionals[2], "password") });
      const ips = await libk.update({ ips: positionals.slice(3), newPassword: values["new-password"] });
      process.stderr.write(`updated ${libk.subdomain}.libk.org\n`);
      process.stdout.write(`${ips.join("\n")}\n`);
      break;
    }
    case "delete": {
      const libk = new Libk({ url: values.url, subdomain: need(positionals[1], "subdomain"), password: need(positionals[2], "password") });
      await libk.delete();
      process.stderr.write(`deleted ${libk.subdomain}.libk.org\n`);
      break;
    }
    default:
      process.stderr.write(`Unknown command ${command}\n`);
      help(1);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
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
  out.write(`${styleText("green", "libk")} v${pkg.version}

  Client for libk.org — claim a subdomain, protect it with a password, point it at IPs

  ${styleText("bold", "Usage:")}

  libk get <subdomain> <password>              Print the record's IPs, one per line
  libk update <subdomain> <password> [ip...]   Point at the given IPs, or the current IP when omitted
  libk delete <subdomain> <password>           Delete the record

  ${styleText("bold", "Options:")}

  --new-password <pw>                          Rotate the password during update
  --url <url>                                  Service endpoint (default https://libk.org/;
                                               6.libk.org forces IPv4, 4.libk.org IPv6)
  -h, --help                                   Show this help
`);
  process.exit(code);
}
