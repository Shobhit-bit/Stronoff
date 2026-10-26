from engine.core import rule, ev, Unknown


@rule(id="ACC-001", title="Non-root account with UID 0", category="ioc", severity="critical", confidence="high",
      why="Any account with UID 0 has full root powers. A second one is a classic backdoor and has no known benign use.",
      fix="Verify who created it (recent useradd events in the logs collector). If it is unexpected, treat the machine as possibly compromised before deleting anything.",
      requires={"accounts": ["integrity.uid0_accounts"]})
def acc_001(ctx):
    for name in ctx.d("accounts")["integrity"]["uid0_accounts"]:
        if name != "root":
            ctx.fail(name, [ev("accounts", "integrity.uid0_accounts", name, "only 'root' has UID 0")], runs_as_root=True)


@rule(id="ACC-002", title="Account can log in with an empty password", category="weakness", severity="critical",
      confidence="high",
      why="An empty password field plus PAM 'nullok' lets anyone log in to this account without a password.",
      fix="Set a password or lock the account (passwd -l <user>) after confirming it is not a service account you rely on. Remove 'nullok' from /etc/pam.d/system-auth.",
      requires={"accounts": ["users"]}, needs_root=("accounts",), optional=("configs",))
def acc_002(ctx):
    users = ctx.d("accounts")["users"]
    if all(u.get("password") is None for u in users):
        raise Unknown("no /etc/shadow data: password info is missing for every account")
    nullok = ctx.get("configs", "pam.summary.nullok_files")        # None when configs is unavailable
    for u in users:
        pw = u.get("password") or {}
        if pw.get("state") == "empty" and u.get("has_login_shell"):
            effective = nullok is None or bool(nullok)             # unknown PAM state -> assume the worst
            note = ("PAM state unknown (configs not collected)" if nullok is None else
                    f"PAM nullok present in: {', '.join(nullok)}" if nullok else "PAM has no 'nullok': login is refused")
            ctx.fail(u["name"], [ev("accounts", f"users[{u['name']}].password.state", "empty", "a set or locked password"),
                                 ev("configs", "pam.summary.nullok_files", note)],
                     severity="critical" if effective else "low", runs_as_root=u.get("uid") == 0)
