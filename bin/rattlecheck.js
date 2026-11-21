#!/usr/bin/env node
import { main } from '../src/cli.js';

main(process.argv.slice(2)).then(
  (code) => {
    if (code !== null) process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`rattlecheck: unexpected error: ${err?.stack ?? err}\n`);
    process.exitCode = 2;
  },
);
