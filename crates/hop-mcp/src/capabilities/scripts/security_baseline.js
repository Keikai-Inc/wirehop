// Security baseline capability — dual mode with push.
//
// Audits: SUID binaries, open ports, failed auth attempts,
// SSH authorized keys, world-writable files in /etc and /usr.

var targets = hop.targets || [];
var isLocal = targets.length === 0;

var auditCmd = [
    'echo "=== SUID ===" && find / -perm -4000 -type f 2>/dev/null | head -30',
    'echo "=== PORTS ===" && (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "no ss/netstat")',
    'echo "=== FAILED_AUTH ===" && (journalctl -u sshd --since "24h ago" 2>/dev/null || tail -100 /var/log/auth.log 2>/dev/null || echo "no auth log") | grep -i "failed" | tail -20',
    'echo "=== SSH_KEYS ===" && for d in /home/*/.ssh /root/.ssh; do [ -f "$d/authorized_keys" ] && echo "$d: $(wc -l < $d/authorized_keys) keys"; done; echo "done"',
    'echo "=== WORLD_WRITABLE ===" && find /etc /usr -perm -o+w -type f 2>/dev/null | head -20; echo "done"'
].join('\n');

function storeBaseline(hostname, output) {
    hop.kv.set('default', 'cap:security:' + hostname + ':latest',
        JSON.stringify({
            host: hostname,
            report: output,
            ts: Date.now()
        })
    );
    hop.log(hostname + ': security baseline collected');
}

if (isLocal) {
    var r = hop.local(auditCmd);
    storeBaseline('self', r.stdout);
} else {
    for (var i = 0; i < targets.length; i++) {
        var r = hop.exec(targets[i].name, auditCmd);
        storeBaseline(targets[i].name, r.stdout);
    }
}
