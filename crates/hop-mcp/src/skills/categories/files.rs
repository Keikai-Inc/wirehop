use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("files/copy-files"),
            category: s("files"),
            title: s("Copy Files"),
            description: s("Copy files to and from remote hosts using hop's encrypted file transfer. Supports push (local to remote) and pull (remote to local)."),
            tags: tags(&["copy", "transfer", "push", "pull", "scp"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Push a file to a remote host",
                    r#"const result = await hop.fs.push("web-1", "./deploy.sh", "/opt/app/deploy.sh");
hop.log(`Push ${result.success ? "succeeded" : "failed"}`);
hop.log(`Transferred ${result.bytesTransferred} bytes`);

const check = await hop.exec("web-1", "ls -la /opt/app/deploy.sh");
hop.log(check.stdout.trim());"#,
                    Some("Push succeeded\nTransferred 2048 bytes\n-rwxr-xr-x 1 deploy deploy 2048 Mar 15 10:30 /opt/app/deploy.sh"),
                ),
                ex(
                    "Pull a file from a remote host",
                    r#"const result = await hop.fs.pull("db-1", "/var/backups/db-latest.sql.gz", "./db-backup.sql.gz");
hop.log(`Pull ${result.success ? "succeeded" : "failed"}`);
hop.log(`Downloaded ${(result.bytesTransferred / 1048576).toFixed(1)} MB`);"#,
                    Some("Pull succeeded\nDownloaded 45.2 MB"),
                ),
            ],
            pitfalls: vec![
                s("File permissions on the remote host depend on the user mode (individual vs shared)."),
                s("Large files transfer in chunks — interrupted transfers must be restarted."),
            ],
            related: tags(&["files/sync-directories", "files/distribute-files"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("files/sync-directories"),
            category: s("files"),
            title: s("Sync Directories"),
            description: s("Synchronize directories between local and remote hosts with delta transfer. Only changed files are transferred."),
            tags: tags(&["sync", "directory", "rsync", "delta", "mirror"]),
            prerequisites: vec![s("files/copy-files")],
            examples: vec![
                ex(
                    "Sync a config directory to a remote host",
                    r#"const configs = ["nginx.conf", "app.conf", "ssl.conf"];
let totalBytes = 0;
for (const file of configs) {
    const result = await hop.fs.push("web-1", `./configs/${file}`, `/etc/myapp/${file}`);
    totalBytes += result.bytesTransferred;
    hop.log(`  ${file}: ${result.bytesTransferred} bytes`);
}
hop.log(`Total transferred: ${totalBytes} bytes`);"#,
                    Some("  nginx.conf: 1024 bytes\n  app.conf: 512 bytes\n  ssl.conf: 256 bytes\nTotal transferred: 1792 bytes"),
                ),
            ],
            pitfalls: vec![
                s("Sync does not delete remote files that were removed locally — manage deletions separately."),
            ],
            related: tags(&["files/copy-files", "files/distribute-files"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("files/distribute-files"),
            category: s("files"),
            title: s("Distribute Files"),
            description: s("Push files to multiple fleet hosts simultaneously. Useful for distributing configs, scripts, or binaries across the fleet."),
            tags: tags(&["distribute", "push", "multi-host", "deploy", "broadcast"]),
            prerequisites: vec![s("files/copy-files"), s("fleet/listing-hosts")],
            examples: vec![
                ex(
                    "Push a config file to all web hosts",
                    r#"const webHosts = await hop.fleet.list("tier:web");
const results = [];
for (const h of webHosts.filter(m => m.online)) {
    const result = await hop.fs.push(h.name, "./nginx.conf", "/etc/nginx/nginx.conf");
    results.push({ host: h.name, ...result });
}

const succeeded = results.filter(r => r.success).length;
const failed = results.filter(r => !r.success).length;
hop.log(`Distributed to ${succeeded} hosts (${failed} failures)`);"#,
                    Some("Distributed to 3 hosts (0 failures)"),
                ),
            ],
            pitfalls: vec![
                s("Distributing to many hosts simultaneously may saturate your uplink bandwidth."),
            ],
            related: tags(&["files/copy-files", "files/template-configs"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("files/collect-files"),
            category: s("files"),
            title: s("Collect Files"),
            description: s("Pull files from multiple fleet hosts to a local directory. Useful for collecting logs, configs, or diagnostic data."),
            tags: tags(&["collect", "pull", "gather", "aggregate", "download"]),
            prerequisites: vec![s("files/copy-files"), s("fleet/listing-hosts")],
            examples: vec![
                ex(
                    "Collect configs from all hosts for diff",
                    r#"const hosts = await hop.fleet.list("tier:web");
for (const h of hosts.filter(m => m.online)) {
    const result = await hop.fs.pull(h.name, "/etc/nginx/nginx.conf", `./collected/${h.name}-nginx.conf`);
    hop.log(`${h.name}: ${result.success ? "collected" : "FAILED"} (${result.bytesTransferred} bytes)`);
}
hop.log("Now compare with: diff collected/*-nginx.conf");"#,
                    Some("web-1: collected (1024 bytes)\nweb-2: collected (1024 bytes)\nweb-3: collected (1098 bytes)\nNow compare with: diff collected/*-nginx.conf"),
                ),
            ],
            pitfalls: vec![
                s("Ensure the local directory exists before pulling files."),
                s("Name collected files uniquely to avoid overwriting."),
            ],
            related: tags(&["files/copy-files", "recipes/log-aggregation"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("files/backup-and-restore"),
            category: s("files"),
            title: s("Backup & Restore Patterns"),
            description: s("Implement backup and restore patterns using hop file transfer. Create timestamped backups and verify integrity."),
            tags: tags(&["backup", "restore", "archive", "snapshot", "recovery"]),
            prerequisites: vec![s("files/copy-files")],
            examples: vec![
                ex(
                    "Backup a database and pull locally",
                    r#"const timestamp = new Date().toISOString().slice(0, 19).replace(/[:-]/g, "");
const backupFile = `db-backup-${timestamp}.sql.gz`;

const dump = await hop.exec("db-1", `pg_dump myapp | gzip > /tmp/${backupFile}`);
if (dump.exitCode !== 0) {
    hop.log(`Backup failed: ${dump.stderr}`);
} else {
    const pull = await hop.fs.pull("db-1", `/tmp/${backupFile}`, `./${backupFile}`);
    hop.log(`Backup pulled: ${(pull.bytesTransferred / 1048576).toFixed(1)} MB`);
    await hop.exec("db-1", `rm /tmp/${backupFile}`);
    hop.log(`Backup saved as ${backupFile}`);
}"#,
                    Some("Backup pulled: 128.5 MB\nBackup saved as db-backup-20250315T103000.sql.gz"),
                ),
            ],
            pitfalls: vec![
                s("Always verify backup integrity before deleting the source."),
                s("Database backups should use the database's native dump tool for consistency."),
            ],
            related: tags(&["files/copy-files", "recipes/disaster-recovery-check"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("files/template-configs"),
            category: s("files"),
            title: s("Template Config Distribution"),
            description: s("Distribute templated configuration files to fleet hosts. Generate host-specific configs from templates."),
            tags: tags(&["template", "config", "generate", "variable", "distribute"]),
            prerequisites: vec![s("files/distribute-files")],
            examples: vec![
                ex(
                    "Distribute host-specific nginx configs",
                    r#"const template = `
server {
    listen 80;
    server_name HOST_NAME.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }
}`;

const webHosts = await hop.fleet.list("tier:web");
for (const h of webHosts.filter(m => m.online)) {
    const config = template.replace(/HOST_NAME/g, h.name);
    await hop.exec(h.name, `cat > /tmp/nginx-site.conf << 'CONF'\n${config}\nCONF`);
    await hop.exec(h.name, "cp /tmp/nginx-site.conf /etc/nginx/sites-enabled/myapp.conf");
    await hop.exec(h.name, "nginx -t && nginx -s reload");
    hop.log(`${h.name}: config deployed and nginx reloaded`);
}"#,
                    Some("web-1: config deployed and nginx reloaded\nweb-2: config deployed and nginx reloaded"),
                ),
            ],
            pitfalls: vec![
                s("Always test config syntax before reloading services (e.g., nginx -t)."),
                s("Template variables must be carefully escaped to avoid shell injection."),
            ],
            related: tags(&["files/distribute-files"]),
            sub_skills: vec![],
        },
    ]
}
