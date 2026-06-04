//! QuickJS runtime factory and sandbox configuration.

pub mod bindings;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hop_core::datastore::Datastore;
use rquickjs::{Context as JsContext, Runtime as QjsRuntime};
use tokio::runtime::Handle;

use crate::backend::BoxedBackend;
use hop_core::sandbox::SandboxPolicy;

/// Sandbox resource limits.
pub struct SandboxLimits {
    pub memory_limit: usize,
    pub max_stack_size: usize,
    pub timeout: Duration,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            memory_limit: 64 * 1024 * 1024,  // 64 MB
            max_stack_size: 1024 * 1024,      // 1 MB
            timeout: Duration::from_secs(30),
        }
    }
}

/// JS runtime wrapper with sandbox enforcement.
pub struct JsRuntime {
    limits: SandboxLimits,
    datastore: Option<Datastore>,
    sandbox: Option<SandboxPolicy>,
    run_as_user: Option<String>,
}

impl Default for JsRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl JsRuntime {
    pub fn new() -> Self {
        Self {
            limits: SandboxLimits::default(),
            datastore: None,
            sandbox: None,
            run_as_user: None,
        }
    }

    pub fn with_limits(limits: SandboxLimits) -> Self {
        Self {
            limits,
            datastore: None,
            sandbox: None,
            run_as_user: None,
        }
    }

    /// Set the datastore for hop.kv.* and hop.ts.* bindings.
    pub fn set_datastore(&mut self, ds: Datastore) {
        self.datastore = Some(ds);
    }

    /// Set the sandbox policy for hop.exec/fleet.exec/local bindings.
    pub fn set_sandbox(&mut self, sandbox: SandboxPolicy) {
        self.sandbox = Some(sandbox);
    }

    /// Set the Unix user for privilege dropping in `hop.local()` calls.
    /// When set and the daemon is root, commands run as this user.
    pub fn set_run_as_user(&mut self, username: String) {
        self.run_as_user = Some(username);
    }

    /// Execute JS code in a fresh sandbox with hop.* bindings.
    ///
    /// Runs QuickJS on a dedicated OS thread to avoid tokio runtime
    /// interaction issues with rquickjs internal locking. The tokio
    /// Handle is captured so synchronous JS bindings can call async
    /// backend methods via `handle.block_on()`.
    pub async fn execute(
        &self,
        code: &str,
        backend: &BoxedBackend,
        timeout: Option<Duration>,
    ) -> Result<String> {
        let timeout = timeout.unwrap_or(self.limits.timeout);
        let code = code.to_string();
        let memory_limit = self.limits.memory_limit;
        let max_stack_size = self.limits.max_stack_size;
        let datastore = self.datastore.clone();
        let sandbox = self.sandbox.clone();
        let run_as_user = self.run_as_user.clone();
        let backend = Arc::clone(backend);
        let handle = Handle::current();

        // Use a oneshot channel to bridge the OS thread back to async
        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            let result = execute_js_sync(
                &code,
                memory_limit,
                max_stack_size,
                timeout,
                datastore.as_ref(),
                Some((backend, handle)),
                sandbox.as_ref(),
                run_as_user.as_deref(),
            );
            let _ = tx.send(result);
        });

        rx.await.context("JS thread panicked")?
    }

    /// Execute JS code without requiring a fleet backend.
    ///
    /// Used by the cron scheduler which only needs JS + datastore bindings.
    pub async fn execute_script(&self, code: &str, timeout: Option<Duration>) -> Result<String> {
        let timeout = timeout.unwrap_or(self.limits.timeout);
        let code = code.to_string();
        let memory_limit = self.limits.memory_limit;
        let max_stack_size = self.limits.max_stack_size;
        let datastore = self.datastore.clone();
        let sandbox = self.sandbox.clone();
        let run_as_user = self.run_as_user.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            let result =
                execute_js_sync(&code, memory_limit, max_stack_size, timeout, datastore.as_ref(), None, sandbox.as_ref(), run_as_user.as_deref());
            let _ = tx.send(result);
        });

        rx.await.context("JS thread panicked")?
    }
}

/// Synchronous JS execution (runs on a dedicated thread).
#[allow(clippy::too_many_arguments)] // cohesive execution context; a struct would just shuffle the args
fn execute_js_sync(
    code: &str,
    memory_limit: usize,
    max_stack_size: usize,
    timeout: Duration,
    datastore: Option<&Datastore>,
    backend: Option<(Arc<dyn crate::backend::OrchestratorBackend>, Handle)>,
    sandbox: Option<&SandboxPolicy>,
    run_as_user: Option<&str>,
) -> Result<String> {
    let rt = QjsRuntime::new().context("Failed to create QuickJS runtime")?;
    rt.set_memory_limit(memory_limit);
    rt.set_max_stack_size(max_stack_size);

    let deadline = std::time::Instant::now() + timeout;
    rt.set_interrupt_handler(Some(Box::new(move || {
        std::time::Instant::now() > deadline
    })));

    let ctx = JsContext::full(&rt).context("Failed to create JS context")?;

    // Install bindings and evaluate code inside ctx.with().
    // IMPORTANT: rt.is_job_pending() / rt.execute_pending_job() must NOT be
    // called inside ctx.with() — ctx.with() holds the runtime Mutex and
    // runtime methods also need it, causing a deadlock.
    let result = ctx.with(|ctx| -> Result<String> {
        bindings::install_hop_bindings(&ctx, datastore, backend, sandbox, run_as_user)?;

        let wrapped = format!("(function() {{\n{code}\n}})()");

        let result: rquickjs::Value = ctx.eval(wrapped).map_err(|e| {
            // Try to extract the actual JS exception message
            let exception_msg = ctx
                .catch()
                .as_exception()
                .map(|ex| {
                    let msg = ex.message().unwrap_or_default();
                    let stack = ex
                        .stack()
                        .unwrap_or_default();
                    if stack.is_empty() {
                        msg
                    } else {
                        format!("{msg}\n{stack}")
                    }
                })
                .unwrap_or_default();
            if exception_msg.is_empty() {
                anyhow::anyhow!("JS execution error: {e}")
            } else {
                anyhow::anyhow!("JS error: {exception_msg}")
            }
        })?;

        value_to_string(&ctx, &result)
    })?;

    // Drive any pending microtasks OUTSIDE ctx.with() to avoid deadlock
    let deadline = std::time::Instant::now() + timeout;
    while rt.is_job_pending() {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("Execution timed out after {}s", timeout.as_secs());
        }
        match rt.execute_pending_job() {
            Ok(false) => break,
            Ok(true) => continue,
            Err(e) => anyhow::bail!("JS async error: {e}"),
        }
    }

    Ok(result)
}

/// Convert a JS value to a string representation.
fn value_to_string<'js>(ctx: &rquickjs::Ctx<'js>, val: &rquickjs::Value<'js>) -> Result<String> {
    if val.is_undefined() || val.is_null() {
        return Ok("undefined".to_string());
    }

    if val.is_string() {
        return Ok(val
            .as_string()
            .map(|s| s.to_string().unwrap_or_default())
            .unwrap_or_default());
    }

    // For objects/arrays, use JSON.stringify
    if val.is_object() || val.is_array() {
        let json: rquickjs::Function = ctx
            .globals()
            .get::<_, rquickjs::Object>("JSON")
            .ok()
            .and_then(|obj| obj.get("stringify").ok())
            .context("JSON.stringify not available")?;

        let result: rquickjs::Value = json
            .call((val.clone(), rquickjs::Value::new_null(ctx.clone()), 2i32))
            .map_err(|e| anyhow::anyhow!("JSON.stringify failed: {e}"))?;

        return Ok(result
            .as_string()
            .map(|s| s.to_string().unwrap_or_default())
            .unwrap_or_else(|| format!("{val:?}")));
    }

    // Numbers, booleans, etc.
    Ok(if let Some(n) = val.as_int() {
        n.to_string()
    } else if let Some(n) = val.as_float() {
        n.to_string()
    } else if let Some(b) = val.as_bool() {
        b.to_string()
    } else {
        format!("{val:?}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local::LocalBackend;
    use crate::backend::BoxedBackend;

    fn test_backend() -> BoxedBackend {
        Arc::new(LocalBackend::new(std::path::PathBuf::from("/tmp/hop-mcp-test")))
    }

    #[test]
    fn quickjs_basic_eval() {
        let rt = QjsRuntime::new().unwrap();
        rt.set_memory_limit(64 * 1024 * 1024);
        let ctx = JsContext::full(&rt).unwrap();
        ctx.with(|ctx| {
            let result: rquickjs::Value = ctx.eval("(function() { return 2 + 2; })()").unwrap();
            assert_eq!(result.as_int(), Some(4));
        });
    }

    #[test]
    fn execute_js_sync_math() {
        let result = execute_js_sync("return 2 + 2", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None).unwrap();
        assert_eq!(result, "4");
    }

    #[test]
    fn execute_js_sync_string() {
        let result = execute_js_sync("return 'hello'", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn execute_js_sync_object() {
        let result = execute_js_sync("return {a: 1, b: 'two'}", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None).unwrap();
        assert!(result.contains("\"a\": 1"));
    }

    #[test]
    fn execute_js_sync_log() {
        let result = execute_js_sync("hop.log('test'); return 'ok'", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None).unwrap();
        assert_eq!(result, "ok");
    }

    #[test]
    fn execute_js_sync_error() {
        let result = execute_js_sync("return {{{", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn execute_js_sync_no_return() {
        let result = execute_js_sync("let x = 42;", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None).unwrap();
        assert_eq!(result, "undefined");
    }

    #[test]
    fn execute_js_sync_array() {
        let result = execute_js_sync("return [1, 2, 3]", 64 * 1024 * 1024, 1024 * 1024, Duration::from_secs(5), None, None, None, None).unwrap();
        assert!(result.contains("["));
        assert!(result.contains("1"));
    }

    #[tokio::test]
    async fn execute_async_math() {
        let runtime = JsRuntime::new();
        let backend = test_backend();
        let result = runtime
            .execute("return 2 + 2", &backend, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(result, "4");
    }

    #[tokio::test]
    async fn execute_async_string() {
        let runtime = JsRuntime::new();
        let backend = test_backend();
        let result = runtime
            .execute("return 'hello world'", &backend, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(result, "hello world");
    }

    #[tokio::test]
    async fn execute_kv_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let mut runtime = JsRuntime::new();
        runtime.set_datastore(ds);
        let backend = test_backend();

        let code = r#"
            try {
                hop.kv.set("test", "greeting", "hello");
                const result = hop.kv.get("test", "greeting");
                return result;
            } catch(e) {
                return "ERROR: " + e.message + " | " + e.stack;
            }
        "#;

        let result = runtime
            .execute(code, &backend, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(result, "hello");
    }

    #[tokio::test]
    async fn execute_ts_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let mut runtime = JsRuntime::new();
        runtime.set_datastore(ds);
        let backend = test_backend();

        let code = r#"
            hop.ts.insert("cpu.usage", 42.5, {host: "web-1"});
            const latest = hop.ts.latest("cpu.usage");
            return latest.value;
        "#;

        let result = runtime
            .execute(code, &backend, Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(result, "42.5");
    }
}
