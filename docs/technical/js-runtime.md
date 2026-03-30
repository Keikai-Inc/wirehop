# JavaScript Runtime

## QuickJS Configuration

hop embeds a QuickJS JavaScript engine (via the `rquickjs` crate) for MCP orchestration scripts and cron jobs. The runtime is configured in `crates/hop-mcp/src/js/mod.rs`.

### Resource Limits

```rust
pub struct SandboxLimits {
    pub memory_limit: usize,      // 64 MiB (64 * 1024 * 1024)
    pub max_stack_size: usize,    // 1 MiB (1024 * 1024)
    pub timeout: Duration,        // 30 seconds
}
```

- **Memory limit**: hard cap on QuickJS heap allocation. Exceeding this causes a JS out-of-memory error.
- **Stack size**: prevents deep recursion from crashing the process.
- **Timeout**: an interrupt handler checks `Instant::now() > deadline` and terminates execution.

## Thread Model

QuickJS runs on a **dedicated OS thread** via `std::thread::spawn`. This is necessary because:

1. rquickjs internal locking conflicts with the tokio runtime when running on worker threads.
2. JS bindings call synchronous blocking operations (redb, reqwest) that would block the async runtime.
3. The `block_on_with_timeout` bridge requires a non-tokio thread to `recv_timeout` on a sync channel.

### Execution Flow

```
[tokio task]                        [OS thread]
     |                                   |
     |-- std::thread::spawn ----------->|
     |                                   |-- create QjsRuntime
     |                                   |-- create JsContext
     |                                   |-- install_hop_bindings()
     |                                   |-- ctx.eval(wrapped_code)
     |                                   |-- drive pending microtasks
     |<-- oneshot::channel::send -------|
     |                                   |
     |-- rx.await ----------------------|
```

Two execution methods:
- `execute(code, backend, timeout)`: full execution with OrchestratorBackend (MCP tool calls)
- `execute_script(code, timeout)`: script-only with datastore bindings (cron jobs)

The code is wrapped in an IIFE: `(function() { <user_code> })()`

### Microtask Draining

After `ctx.eval()`, pending microtasks are driven **outside** `ctx.with()` to avoid a deadlock:

```rust
// ctx.with() holds the runtime Mutex
// rt.is_job_pending() also needs the Mutex
// Therefore: drain jobs AFTER ctx.with() returns

while rt.is_job_pending() {
    if Instant::now() > deadline { bail!("timed out"); }
    match rt.execute_pending_job() {
        Ok(false) => break,   // No more jobs
        Ok(true) => continue, // More jobs
        Err(e) => bail!("JS async error: {e}"),
    }
}
```

## Async Bridge: block_on_with_timeout

JS bindings that call async backend methods use this function to bridge between the synchronous JS thread and the tokio runtime:

```rust
fn block_on_with_timeout<F, T>(handle: &Handle, timeout: Duration, fut: F) -> Result<T>
```

Implementation:
1. Create a `std::sync::mpsc::sync_channel(1)`
2. Spawn the async future on the tokio runtime via `handle.spawn()`
3. Block the JS thread with `rx.recv_timeout(timeout)`
4. On timeout (60 seconds default): return error
5. On disconnect (task panic): return error

This is preferred over `Handle::block_on` + `tokio::time::timeout` because tokio timer wakeups are unreliable on a non-tokio thread.

```rust
const BLOCK_ON_TIMEOUT: Duration = Duration::from_secs(60);
```

## Binding Architecture

### Installation Flow

`install_hop_bindings()` in `crates/hop-mcp/src/js/bindings.rs`:

```
1. Create `hop` object
2. Install hop.log, hop.sleep (always available)
3. Install hop.id (from backend or stub)
4. Set `hop` on globals
5. If backend available:
   a. install_live_raw_bindings() -- __hop_exec, __hop_fleet_list, etc.
   b. install_backend_js_wrappers() -- hop.exec, hop.fleet.*, hop.admin.*, etc.
6. If no backend:
   a. install_stub_bindings() -- throw errors for backend-dependent methods
7. install_local_binding() -- hop.local(command)
8. install_http_binding() -- hop.http(url, options)
9. If datastore available:
   a. install_datastore_raw() -- __hop_kv_*, __hop_ts_*, __hop_secrets_*, __hop_cron_*
   b. install_datastore_js_wrappers() -- hop.kv.*, hop.ts.*, hop.secrets.*, hop.cron.*
10. If no datastore:
    a. install_datastore_stubs()
11. remove_dangerous_globals()
```

### Raw __hop_* to JS Wrapper Pattern

Each binding follows a two-layer pattern:

1. **Raw Rust function** (`__hop_exec`): registered on `ctx.globals()`, returns JSON strings.
2. **JS wrapper** (`hop.exec`): calls the raw function and parses the JSON.

```javascript
// JS wrapper installed via ctx.eval()
hop.exec = function(host, command) {
    return JSON.parse(__hop_exec(host, command));
};
```

This keeps the Rust FFI surface simple (string in, string out) while providing a ergonomic JS API.

## Binding Categories

### Utility

| Binding | Description |
|---|---|
| `hop.log(...args)` | Write to stderr (`eprintln!`), not visible to MCP client |
| `hop.sleep(ms)` | Synchronous sleep via `std::thread::sleep` |
| `hop.id()` | Returns the node's public key string |

### Backend (requires OrchestratorBackend)

| Binding | Raw Function | Description |
|---|---|---|
| `hop.exec(host, command)` | `__hop_exec` | Execute command on remote host, returns `{stdout, stderr, exit_code}` |
| `hop.fleet.list(tag?)` | `__hop_fleet_list` | List fleet members, optional tag filter |
| `hop.fleet.exec(group, command)` | `__hop_fleet_exec` | Execute on all hosts matching group tag |
| `hop.admin.status(host)` | `__hop_admin_status` | Get host status (version, peers, sessions) |
| `hop.admin.peers(host)` | `__hop_admin_peers` | List authorized peers |
| `hop.admin.invite(host, username?, role?)` | `__hop_admin_invite` | Create invite on remote host |
| `hop.admin.removePeer(host, prefix)` | `__hop_admin_remove_peer` | Remove peer by ID prefix |
| `hop.roles.list(host)` | `__hop_roles_list` | List role definitions |
| `hop.roles.delete(host, name)` | `__hop_roles_delete` | Delete a role |
| `hop.metrics.push(points)` | `__hop_metrics_push` | Push metric points to orchestrator |
| `hop.local(command)` | `__hop_local` | Execute on local machine with sandbox |

When a sandbox policy is set, `hop.exec` and `hop.fleet.exec` use the `_sandboxed` variants, and `hop.local` validates against the policy and applies OS-level sandboxing.

### Datastore

| Binding | Raw Function | Description |
|---|---|---|
| `hop.kv.get(ns, key)` | `__hop_kv_get` | Get value (returns parsed JSON, not raw entry) |
| `hop.kv.set(ns, key, value, contentType?)` | `__hop_kv_set` | Set value (auto JSON.stringify) |
| `hop.kv.delete(ns, key)` | `__hop_kv_delete` | Delete key, returns boolean |
| `hop.kv.list(ns, prefix?)` | `__hop_kv_list` | List entries matching prefix |
| `hop.ts.insert(metric, value, tags?)` | `__hop_ts_insert` | Insert time-series point |
| `hop.ts.query(metric, start, end, options?)` | `__hop_ts_query` | Query range with optional tags/limit |
| `hop.ts.latest(metric)` | `__hop_ts_latest` | Get most recent point |
| `hop.cron.list()` | `__hop_cron_list` | List cron jobs (id, name, schedule, enabled) |
| `hop.secrets.get(name)` | `__hop_secrets_get` | Get decrypted secret value |
| `hop.secrets.set(name, value)` | `__hop_secrets_set` | Encrypt and store secret |
| `hop.secrets.delete(name)` | `__hop_secrets_delete` | Delete secret |
| `hop.secrets.list()` | `__hop_secrets_list` | List secret names (not values) |

### HTTP

```rust
fn install_http_binding(ctx, sandbox)
```

| Binding | Description |
|---|---|
| `hop.http(url, options?)` | Full HTTP request with options: `{method, headers, body, json, bearer}` |
| `hop.http.get(url, opts?)` | Convenience GET |
| `hop.http.post(url, opts?)` | Convenience POST |
| `hop.http.put(url, opts?)` | Convenience PUT |
| `hop.http.delete(url, opts?)` | Convenience DELETE |

Returns `{ status, headers, body, json() }` where `json()` parses the body.

Implementation: `reqwest::blocking::Client` with 30-second timeout. Safe on the JS thread because it is a plain OS thread, not a tokio worker.

**Sandbox enforcement**: when `SandboxPolicy.no_network` is true, `hop.http` throws `"network access denied by sandbox policy"`.

Supported methods: GET, POST, PUT, DELETE, PATCH, HEAD.

## Dangerous Globals Removal

After all bindings are installed, `remove_dangerous_globals()` removes globals that could escape the sandbox:

```rust
fn remove_dangerous_globals(ctx: &Ctx<'_>) -> Result<()> {
    let dangerous = ["require", "process", "Deno", "Bun"];
    for name in dangerous {
        let _ = globals.remove::<String>(name.to_string());
    }
    Ok(())
}
```

| Global | Reason for removal |
|---|---|
| `require` | Could load arbitrary Node.js modules |
| `process` | Node.js process access (env, argv, exit) |
| `Deno` | Deno runtime access |
| `Bun` | Bun runtime access |

QuickJS does not natively provide these globals, but they are removed defensively in case future versions or extensions add them.

*Last updated: v0.4.3*
