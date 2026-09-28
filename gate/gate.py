#!/usr/bin/env python3
"""AGENTS APP foundation gate (runs in GitHub Actions; always executed from the BASE branch, never from the PR head).

Verdicts (last line of output and of the step summary):
  DONE              all must-criteria Verified on the PR head SHA, tamper + canary clean
  AMENDMENT-OK      the PR changes only protected paths, the head task file lists their exact hashes, and the policy owner
                    APPROVED the head SHA (owner decision right, enforced mechanically here and by CODEOWNERS/ruleset)
  BLOCKED:EVIDENCE  a must-criterion is Unknown (no oracle, crash, timeout) or required evidence input is missing
  BLOCKED:DECISION  the PR does not map to an approved contract / changes a path no amendment can cover
  FAIL:<reason>     tamper, canary, oracle failure or policy violation
Exit status is 0 only for DONE and AMENDMENT-OK, so the required `gate` check cannot pass in any other state.
Evidence (criterion statuses bound to head SHA + contract hash) is printed as JSON and written to the job summary.
"""
import hashlib, json, os, re, subprocess, sys, tempfile, time, urllib.request, fnmatch

REPO = os.environ.get("GITHUB_REPOSITORY", "")
TOKEN = os.environ.get("GH_TOKEN", "")
# The canary is a fresh random value per gate run, given only to the preview process (never stored, never in the repository):
# any appearance in a client-visible response proves a server-side secret reached the client.
CANARY = "AGENTSAPP-CANARY-" + __import__("secrets").token_hex(20)
EVENT = json.load(open(os.environ["GITHUB_EVENT_PATH"])) if os.environ.get("GITHUB_EVENT_PATH") else {}
PR = EVENT.get("pull_request") or {}
WORK = os.path.abspath(os.environ.get("GATE_WORK", "."))

PREVIEW_USER = os.environ.get("GATE_PREVIEW_USER", "gatepreview")
PROTECTED = ["oracle/**", "baselines/**", "tasks/**", ".github/**", "CODEOWNERS", "gate/**", "policy.json"]
NEVER_VIA_PR = [".github/**", "gate/**", "CODEOWNERS", "policy.json"]   # changed only by the owner outside the PR path

def match(path, pats):
    for p in pats:
        if p.endswith("/**"):
            if path == p[:-3] or path.startswith(p[:-2]): return True
        elif fnmatch.fnmatchcase(path, p): return True
    return False

def git(*a, check=True):
    r = subprocess.run(["git", *a], cwd=WORK, capture_output=True)
    if check and r.returncode != 0: raise RuntimeError("git %s failed: %s" % (a[0], r.stderr.decode(errors="replace")[:300]))
    return r.stdout

def show(sha, path):
    r = subprocess.run(["git", "show", "%s:%s" % (sha, path)], cwd=WORK, capture_output=True)
    return r.stdout if r.returncode == 0 else None

def sha256(b): return hashlib.sha256(b).hexdigest()

def api(path):
    req = urllib.request.Request("https://api.github.com" + path, headers={"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=30) as r: return json.load(r)

OUT = {"repo": REPO, "pr": PR.get("number"), "head_sha": None, "base_sha": None, "task": None, "contract_sha256": None, "criteria": {}, "checks": {}, "verdict": None, "reasons": []}

def finish(verdict, reason=None):
    OUT["verdict"] = verdict
    if reason: OUT["reasons"].append(reason)
    js = json.dumps(OUT, sort_keys=True, indent=1)
    print(js)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f: f.write("## gate evidence\n```json\n" + js + "\n```\n\n**VERDICT: %s**\n" % verdict)
    print("::notice title=gate-verdict::%s" % verdict)
    print("::notice title=gate-evidence::%s" % json.dumps({k: OUT[k] for k in ("head_sha", "base_sha", "task", "contract_sha256", "criteria", "reasons")}, sort_keys=True, separators=(",", ":"))[:3500])
    print("GATE VERDICT: " + verdict)
    sys.exit(0 if verdict in ("DONE", "AMENDMENT-OK") else 1)

def main():
    head = PR.get("head", {}).get("sha"); base = PR.get("base", {}).get("sha"); branch = PR.get("head", {}).get("ref", "")
    OUT["head_sha"], OUT["base_sha"] = head, base
    if not (head and base and REPO): finish("BLOCKED:EVIDENCE", "event lacks pull_request head/base")
    if PR.get("head", {}).get("repo", {}).get("full_name") != REPO: finish("FAIL:FOREIGN-HEAD", "PR head is not a branch of this repository")
    policy = json.loads(show(base, "policy.json") or b"null")
    if not policy or not policy.get("owner_login"): finish("BLOCKED:EVIDENCE", "base policy.json missing owner_login")
    mb = git("merge-base", base, head).decode().strip()
    changed = [p for p in git("-c", "core.quotePath=false", "diff", "--name-only", "-z", "--no-renames", mb, head).decode("utf-8", "surrogateescape").split("\0") if p]
    OUT["checks"]["changed_files"] = changed
    prot = [p for p in changed if match(p, PROTECTED)]
    OUT["checks"]["protected_changed"] = prot
    never = [p for p in prot if match(p, NEVER_VIA_PR)]
    if never: finish("FAIL:TAMPER", "PR changes owner-only paths %s" % never)
    # --- canary scan over every file of the head tree (client-visible surfaces are also checked at preview time) ---
    hits = []
    for p in [x for x in git("ls-tree", "-r", "-z", "--name-only", head).decode("utf-8", "surrogateescape").split("\0") if x]:
        b = show(head, p)
        if b is not None and CANARY.encode() in b: hits.append(p)
    OUT["checks"]["canary_in_tree"] = hits
    if hits: finish("FAIL:CANARY", "canary value present in repository files %s" % hits)
    # --- tamper gate: protected-path changes need an exact-hash amendment + owner approval of this head SHA ---
    if prot:
        task_files = sorted({p.split("/")[1] for p in prot if p.startswith("tasks/") and p.count("/") >= 2})
        tid = (re.match(r"^amend/(T-[A-Za-z0-9]+)/", branch) or [None, None])[1]
        if not tid or (task_files and task_files != [tid]): finish("FAIL:TAMPER", "protected change outside an amend/<task>/ branch or across tasks")
        task = json.loads(show(head, "tasks/%s/task.json" % tid) or b"null")
        am = (task or {}).get("amendments") or []
        listed = am[-1].get("files", {}) if am else {}
        for p in prot:
            if p == "tasks/%s/task.json" % tid: continue
            b = show(head, p)
            if listed.get(p) != (sha256(b) if b is not None else "DELETED"): finish("FAIL:TAMPER", "protected file %s not covered by the latest amendment hash" % p)
        try: reviews = api("/repos/%s/pulls/%s/reviews?per_page=100" % (REPO, PR["number"]))
        except Exception as e: finish("BLOCKED:EVIDENCE", "cannot read reviews: %s" % str(e)[:120])
        mine = [r for r in reviews if (r.get("user") or {}).get("login", "").lower() == policy["owner_login"].lower() and r.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")]
        last = max(mine, key=lambda r: (r.get("submitted_at") or "", r.get("id") or 0)) if mine else None
        ok = bool(last) and last.get("state") == "APPROVED" and last.get("commit_id") == head   # the owner's LATEST decisive review approves THIS head
        OUT["checks"]["owner_approval_of_head"] = bool(ok)
        if not ok: finish("BLOCKED:DECISION", "protected change awaits the owner's approval of head %s" % head)
        if [p for p in changed if p not in prot]: finish("FAIL:TAMPER", "an amendment PR may change only protected files")
        finish("AMENDMENT-OK")
    # --- task / contract binding (from BASE only: the PR cannot redefine success) ---
    m = re.match(r"^task/(T-[A-Za-z0-9]+)/", branch)
    if not m: finish("BLOCKED:DECISION", "branch %r does not name an approved task (task/<T-id>/...)" % branch)
    tid = m.group(1); OUT["task"] = tid
    task = json.loads(show(base, "tasks/%s/task.json" % tid) or b"null")
    contract_b = show(base, "tasks/%s/contract.json" % tid)
    if not task or contract_b is None: finish("BLOCKED:DECISION", "no approved contract for %s on the base branch" % tid)
    OUT["contract_sha256"] = sha256(contract_b)
    if (task.get("approval") or {}).get("contract_sha256") != sha256(contract_b) or (task.get("approval") or {}).get("by", "").lower() != policy["owner_login"].lower():
        finish("BLOCKED:DECISION", "contract hash is not the owner-approved hash")
    contract = json.loads(contract_b)
    allowed = contract.get("scope", {}).get("paths") or []
    outside = [p for p in changed if p not in prot and not match(p, allowed)]
    if outside: finish("BLOCKED:DECISION", "changes outside the contract scope %s" % outside)
    # --- preview from the HEAD tree, oracles from the BASE tree ---
    # The PR head code is untrusted: it runs as a separate unprivileged user that cannot read or write the gate's files (oracles,
    # evidence, step summary), cannot read the gate's environment (GH_TOKEN) and cannot signal gate processes.
    tmp = tempfile.mkdtemp(prefix="gate-", dir=os.environ.get("RUNNER_TEMP") or None)   # 0700, runner-owned, outside /tmp: oracles live here
    oradir = os.path.join(tmp, "oracle"); os.makedirs(oradir)
    headdir = tempfile.mkdtemp(prefix="gate-head-"); os.chmod(headdir, 0o755)   # readable, not writable, by the preview user
    subprocess.run("git archive %s | tar -x --no-same-owner --no-same-permissions -C %s && chmod -R go-w,a+rX %s" % (head, headdir, headdir), shell=True, cwd=WORK, check=True)
    if subprocess.run(["id", "-u", PREVIEW_USER], capture_output=True).returncode != 0:
        subprocess.run(["sudo", "-n", "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", PREVIEW_USER], check=True)
    oracles = task.get("oracles") or {}
    for crit, rel in oracles.items():
        b = show(base, rel)
        if b is not None:
            d = os.path.join(oradir, os.path.dirname(rel)); os.makedirs(d, exist_ok=True); open(os.path.join(oradir, rel), "wb").write(b)
    pv = contract.get("preview") or {}
    port = int(pv.get("port", 8080))
    node = subprocess.run(["which", "node"], capture_output=True).stdout.decode().strip()
    # the preview user may not send anything off the machine (the canary must not leave by any channel we do not scan) and gets
    # the canary through stdin, never through argv (argv is readable by every local user)
    for fw in ("iptables", "ip6tables"):
        for rule in (["-o", "lo", "-p", "udp", "--dport", "53"], ["-o", "lo", "-p", "tcp", "--dport", "53"], ["!", "-o", "lo"]):
            if subprocess.run(["sudo", "-n", fw, "-I", "OUTPUT", "-m", "owner", "--uid-owner", PREVIEW_USER] + rule + ["-j", "REJECT"], capture_output=True).returncode != 0:
                finish("BLOCKED:EVIDENCE", "could not confine the preview's network egress (%s)" % fw)
    loader = "const fs=require('fs');process.env.APP_SECRET_CANARY=fs.readFileSync(0,'utf8');import(require('path').resolve(process.argv[1]))"
    srv = subprocess.Popen(["sudo", "-n", "-u", PREVIEW_USER, "env", "-i", "PATH=/usr/bin:/bin:" + os.path.dirname(node), "PORT=%d" % port, "HOME=/nonexistent",
                            node, "-e", loader, pv.get("entry", "app/server.mjs")], cwd=headdir, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv.stdin.write(CANARY.encode()); srv.stdin.close()
    base_url = "http://127.0.0.1:%d" % port
    up = False
    for _ in range(40):
        try: urllib.request.urlopen(base_url + pv.get("ready", "/"), timeout=2); up = True; break
        except urllib.error.HTTPError: up = True; break
        except Exception: time.sleep(0.5)
    try:
        if not up: finish("BLOCKED:EVIDENCE", "preview did not start")
        # canary on client-visible HTTP responses of the preview
        seen = []
        for route in contract.get("canary_routes", ["/"]):
            try:
                with urllib.request.urlopen(base_url + route, timeout=10) as r: body = r.read(); hdr = str(r.headers)
            except urllib.error.HTTPError as e: body = e.read(); hdr = str(e.headers)
            except Exception: body, hdr = b"", ""
            if CANARY.encode() in body or CANARY in hdr: seen.append(route)
        OUT["checks"]["canary_in_preview_responses"] = seen
        if seen: finish("FAIL:CANARY", "canary value reached the client on %s" % seen)
        # run each oracle once; parse per-criterion JSON lines
        results, ran = {}, {}
        for crit in [c["id"] for c in contract.get("criteria", []) if c.get("priority") == "must"]:
            rel = oracles.get(crit)
            if not rel or not os.path.exists(os.path.join(oradir, rel)):
                OUT["criteria"][crit] = {"status": "Unknown", "reason": "no owner-approved oracle"}; continue
            if rel not in ran:
                try:
                    r = subprocess.run(["node", os.path.join(oradir, rel), base_url], capture_output=True, timeout=90, env={"PATH": os.environ["PATH"], "HOME": tmp})
                    ran[rel] = (r.returncode, r.stdout.decode(errors="replace"))
                except subprocess.TimeoutExpired: ran[rel] = (None, "")
            rc, so = ran[rel]
            seen = []
            for line in so.splitlines():
                try: j = json.loads(line)
                except Exception: continue
                if isinstance(j, dict) and j.get("criterion") == crit: seen.append(j.get("result"))
            st = seen[0] if rc == 0 and len(seen) == 1 else None   # crash, missing, duplicate or conflicting output => Unknown
            OUT["criteria"][crit] = {"status": {"pass": "Verified", "fail": "Not verified"}.get(st, "Unknown"), "oracle": rel, "oracle_sha256": sha256(show(base, rel)), "exit": rc}
    finally:
        subprocess.run(["sudo", "-n", "pkill", "-KILL", "-u", PREVIEW_USER], capture_output=True)
        try: srv.wait(5)
        except Exception: srv.kill()
    sts = [v["status"] for v in OUT["criteria"].values()]
    if not sts: finish("BLOCKED:DECISION", "contract has no must-criteria")
    if "Not verified" in sts: finish("FAIL:ORACLE", "a must-criterion failed its oracle")
    if "Unknown" in sts: finish("BLOCKED:EVIDENCE", "a must-criterion is Unknown")
    finish("DONE")

if __name__ == "__main__":
    try: main()
    except SystemExit: raise
    except Exception as e: finish("BLOCKED:EVIDENCE", "gate infrastructure error: %s" % str(e)[:200])
# tampered by a task branch
