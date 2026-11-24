"""Sensitive-file / information-exposure probes.

All probes are plain GETs of well-known paths. A hit requires HTTP 200,
a content signature where one exists, and a body that differs from the
site's soft-404 baseline (see _common.is_real_hit).
"""
import re

from ._common import F, bogus, is_real_hit, register


def _get(ctx, path):
    return ctx.client.get(ctx.target + path)


def _hit(ctx, path, signatures=()):
    resp = _get(ctx, path)
    if not is_real_hit(ctx, resp):
        return None
    if signatures:
        body = resp.text or ""
        if not any(sig in body for sig in signatures):
            return None
    return resp


def _one(ctx, path, severity, evidence, description, remediation, cwe, signatures=()):
    resp = _hit(ctx, path, signatures)
    if resp is None:
        return []
    return [F(severity, ctx.target + path, evidence, description, remediation, cwe)]


GIT_DESC = ("Source-control metadata is publicly downloadable; attackers can "
            "reconstruct the full source code and history of the site.")
GIT_FIX = "Block access to /.git/ at the web server or deploy without the .git directory."


@register("exp-git-head", "Exposed .git/HEAD (source control metadata)")
def check_git_head(ctx):
    return _one(ctx, "/.git/HEAD", "high",
                "/.git/HEAD served, starts with 'ref:'",
                GIT_DESC, GIT_FIX, "CWE-527", signatures=("ref:",))


@register("exp-git-config", "Exposed .git/config (repository configuration)")
def check_git_config(ctx):
    return _one(ctx, "/.git/config", "high",
                "/.git/config served with [core] section",
                "The git config can reveal remote URLs (sometimes with "
                "embedded credentials) and confirms full repo exposure.",
                GIT_FIX, "CWE-527", signatures=("[core]",))


@register("exp-env-file", "Exposed .env file (secrets)")
def check_env(ctx):
    resp = _hit(ctx, "/.env")
    if resp is None:
        return []
    body = resp.text or ""
    if not re.search(r"^[A-Z_][A-Z0-9_]*=", body, re.M):
        return []
    keys = re.findall(r"^([A-Z_][A-Z0-9_]*)=", body, re.M)[:5]
    return [F("critical", ctx.target + "/.env",
              ".env served; variable names seen: %s" % ", ".join(keys),
              ".env files typically hold database passwords, API keys and app "
              "secrets. Anyone can download this file.",
              "Move .env outside the web root and deny access to dotfiles.", "CWE-798")]


@register("exp-env-backup", "Exposed .env backup variant")
def check_env_backup(ctx):
    for path in ("/.env.bak", "/.env.old", "/.env.save", "/.env.example.bak"):
        resp = _hit(ctx, path)
        if resp is not None and re.search(r"^[A-Z_][A-Z0-9_]*=", resp.text or "", re.M):
            return [F("high", ctx.target + path,
                      "%s served with KEY=value content" % path,
                      "A backup copy of the environment file is downloadable "
                      "and likely contains production secrets.",
                      "Remove backup files from the web root and deny dotfile access.", "CWE-798")]
    return []


@register("exp-backup-sql", "Exposed SQL backup file")
def check_backup_sql(ctx):
    return _one(ctx, "/backup.sql", "high",
                "/backup.sql served with SQL statements",
                "A full database dump is publicly downloadable, exposing all "
                "stored data including password hashes.",
                "Remove database dumps from the web root; store backups off-server.",
                "CWE-527", signatures=("CREATE TABLE", "INSERT INTO", "mysqldump"))


@register("exp-backup-zip", "Exposed backup archive")
def check_backup_zip(ctx):
    resp = _get(ctx, "/backup.zip")
    if not is_real_hit(ctx, resp):
        return []
    ctype = resp.headers.get("content-type", "")
    if "zip" not in ctype and "octet-stream" not in ctype:
        return []
    return [F("high", ctx.target + "/backup.zip",
              "/backup.zip served, Content-Type: %s" % ctype,
              "A site archive usually contains full source code and "
              "configuration, including embedded secrets.",
              "Remove archives from the web root; store backups off-server.", "CWE-527")]


@register("exp-ds-store", "Exposed .DS_Store file")
def check_ds_store(ctx):
    resp = _get(ctx, "/.DS_Store")
    if resp is None or resp.status != 200:
        return []
    if "Bud1" not in (resp.text or "")[:16] and not is_real_hit(ctx, resp):
        return []
    return [F("low", ctx.target + "/.DS_Store",
              "/.DS_Store downloadable",
              ".DS_Store files leak directory listings and filenames, helping "
              "attackers map the site structure.",
              "Delete .DS_Store files and deny access to dotfiles.", "CWE-200")]


@register("exp-wp-config-backup", "Exposed wp-config backup")
def check_wp_config(ctx):
    return _one(ctx, "/wp-config.php.bak", "critical",
                "/wp-config.php.bak served",
                "wp-config backups contain live WordPress database credentials "
                "and authentication salts in plain text.",
                "Remove the backup file and rotate the database password and salts.",
                "CWE-798", signatures=("DB_PASSWORD", "define"))


@register("exp-phpinfo", "Exposed phpinfo() page")
def check_phpinfo(ctx):
    return _one(ctx, "/phpinfo.php", "medium",
                "/phpinfo.php served with PHP configuration",
                "phpinfo() discloses PHP version, loaded modules, paths and "
                "environment variables — a full reconnaissance gift.",
                "Delete phpinfo pages from production.", "CWE-200",
                signatures=("PHP Version", "phpinfo()"))


@register("exp-svn-entries", "Exposed .svn metadata")
def check_svn(ctx):
    return _one(ctx, "/.svn/entries", "medium",
                "/.svn/entries served",
                "Subversion metadata lets attackers enumerate and download "
                "the site's source files.",
                "Block access to /.svn/ or deploy from an export.", "CWE-527",
                signatures=("svn", "dir"))


@register("exp-htaccess", "Exposed .htaccess file")
def check_htaccess(ctx):
    return _one(ctx, "/.htaccess", "low",
                "/.htaccess downloadable",
                "Server configuration disclosure reveals rewrite rules and "
                "access restrictions, aiding targeted attacks.",
                "Configure the server to deny access to .ht* files.", "CWE-200",
                signatures=("Rewrite", "Deny", "Order", "AuthType"))


@register("exp-server-status", "Exposed Apache server-status page")
def check_server_status(ctx):
    return _one(ctx, "/server-status", "medium",
                "/server-status served",
                "mod_status leaks live request URLs, client IPs and server "
                " internals to anyone who asks.",
                "Restrict /server-status to localhost.", "CWE-200",
                signatures=("Apache Status", "Server uptime"))


@register("exp-actuator-env", "Exposed Spring Boot Actuator /env")
def check_actuator(ctx):
    resp = _hit(ctx, "/actuator/env")
    if resp is None or '"propertySources"' not in (resp.text or "") \
            and '"systemProperties"' not in (resp.text or ""):
        return []
    return [F("high", ctx.target + "/actuator/env",
              "/actuator/env returns environment JSON",
              "The Actuator env endpoint discloses configuration properties, "
              "often including credentials, and pairs with other actuator "
              "endpoints for deeper compromise.",
              "Disable or secure Actuator endpoints (management.endpoints.web.exposure).", "CWE-200")]


@register("exp-composer-json", "Exposed composer.json (dependency disclosure)")
def check_composer(ctx):
    return _one(ctx, "/composer.json", "low",
                "/composer.json served",
                "The dependency manifest reveals exact package versions, "
                "which attackers match against known vulnerabilities.",
                "Deny access to composer.json/composer.lock from the web.", "CWE-200",
                signatures=('"require"', '"name"'))


@register("exp-package-json", "Exposed package.json (dependency disclosure)")
def check_package(ctx):
    return _one(ctx, "/package.json", "low",
                "/package.json served",
                "The dependency manifest reveals exact package versions and "
                "internal scripts, aiding targeted attacks.",
                "Do not serve package.json from the web root.", "CWE-200",
                signatures=('"dependencies"', '"scripts"'))


@register("exp-dir-listing", "Directory listing enabled")
def check_dir_listing(ctx):
    for path in ("/", "/images/", "/uploads/", "/static/", "/assets/", "/backup/"):
        resp = _get(ctx, path)
        body = resp.text or ""
        if resp.status == 200 and ("Index of /" in body or "<title>Index of" in body):
            return [F("medium", ctx.target + path,
                      "Auto-index page at %s ('Index of /')" % path,
                      "Directory listing exposes every file name in the "
                      "directory, including backups and uploads not meant "
                      "to be public.",
                      "Disable autoindex (Options -Indexes / autoindex off).", "CWE-548")]
    return []


@register("exp-homepage-backup", "Backup copy of the homepage accessible")
def check_homepage_backup(ctx):
    candidates = ("/index.php.bak", "/index.php.old", "/index.php.save",
                  "/index.php~", "/index.html.bak", "/index.html~",
                  "/index.htm.bak")
    for path in candidates:
        resp = _get(ctx, path)
        if is_real_hit(ctx, resp):
            return [F("medium", ctx.target + path,
                      "%s served (status 200, differs from 404 baseline)" % path,
                      "Backup copies of server-side pages are served as plain "
                      "text, disclosing source code and embedded secrets.",
                      "Remove editor/backup files from the web root.", "CWE-527")]
    return []


@register("exp-verbose-error", "Verbose error / stack trace on a bogus path")
def check_verbose_error(ctx):
    body = bogus(ctx).text or ""
    signatures = ("Traceback (most recent call last)", "Fatal error:",
                  "stack trace", "System.Exception", "at org.apache.",
                  "You're seeing this error because you have DEBUG",
                  "Whoops, looks like something went wrong",
                  "SQLSTATE[", "Uncaught Exception", "Warning: include(")
    found = [s for s in signatures if s in body]
    if not found:
        return []
    return [F("medium", ctx.target + "/" + ctx.marker + "-notfound",
              "Error page contains: %s" % found[0],
              "Detailed error output leaks framework versions, file paths and "
              "sometimes SQL fragments, accelerating targeted attacks.",
              "Disable debug mode in production; log errors server-side only.", "CWE-209")]


@register("exp-security-txt-missing", "security.txt missing")
def check_security_txt(ctx):
    if bogus(ctx).status == 0:
        return []
    for path in ("/.well-known/security.txt", "/security.txt"):
        resp = _get(ctx, path)
        if resp.status == 200:
            return []
    return [F("info", ctx.target + "/.well-known/security.txt",
              "No security.txt at /.well-known/security.txt or /security.txt",
              "Without security.txt (RFC 9116), researchers have no official "
              "channel to report vulnerabilities.",
              "Publish a security.txt with a monitored contact address.", "CWE-1059")]


@register("exp-robots-info", "robots.txt discloses sensitive paths")
def check_robots(ctx):
    resp = _get(ctx, "/robots.txt")
    if resp.status != 200:
        return []
    paths = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", resp.text or "")
    interesting = [p for p in paths
                   if any(k in p.lower() for k in
                          ("admin", "backup", "config", "private", "api",
                           "internal", ".git", "wp-admin", "login"))]
    if not interesting:
        return []
    return [F("info", ctx.target + "/robots.txt",
              "Disallow entries reveal: %s" % ", ".join(interesting[:5]),
              "robots.txt is public; Disallow entries advertise the exact "
              "paths the operator considers sensitive.",
              "Do not rely on robots.txt for secrecy; protect the paths themselves.", "CWE-200")]


@register("exp-crossdomain-xml", "Permissive crossdomain.xml (Flash cross-domain policy)")
def check_crossdomain(ctx):
    resp = _hit(ctx, "/crossdomain.xml", signatures=("cross-domain-policy",))
    if resp is None:
        return []
    if 'domain="*"' not in (resp.text or ""):
        return []
    return [F("low", ctx.target + "/crossdomain.xml",
              'crossdomain.xml allows domain="*"',
              "A wildcard Flash cross-domain policy lets any Flash content "
              "read this origin's responses (legacy, but still honored by "
              "some clients).",
              "Restrict crossdomain.xml to trusted domains or delete it.", "CWE-942")]
