#!/usr/bin/env node
// Shim: exec the real `hop` binary, passing through args, stdio, and exit code.
//
// Two resolution paths, in order:
//   1. the binary this package downloaded at install time
//   2. `hop` already on PATH (WIREHOP_SKIP_DOWNLOAD installs, Homebrew, curl|bash)
//
// stdio is inherited so `hop mcp` speaks the MCP stdio protocol straight
// through this process without buffering or mangling.

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const local = path.join(__dirname, process.platform === 'win32' ? 'hop.exe' : 'hop');
const cmd = fs.existsSync(local) ? local : 'hop';

const res = spawnSync(cmd, process.argv.slice(2), { stdio: 'inherit' });

if (res.error) {
  if (res.error.code === 'ENOENT') {
    console.error(
      'wirehop: no `hop` binary found.\n' +
        '  The download may have been skipped (WIREHOP_SKIP_DOWNLOAD=1) or failed.\n' +
        '  Install one with:  curl -fsSL https://wirehop.org/install.sh | bash'
    );
    process.exit(127);
  }
  console.error(`wirehop: ${res.error.message}`);
  process.exit(1);
}

// Preserve signal-death as a shell would report it.
if (res.signal) process.kill(process.pid, res.signal);
process.exit(res.status === null ? 1 : res.status);
