"""Analyze security findings from the LastPass extension scan."""

import re
import os
import json

EXT_ROOT = "output/workspace/extension"

def analyze_new_function(fpath, label):
    """Find and contextualize all new Function() calls in a file."""
    print(f"\n{'='*70}")
    print(f"ANALYZING: {label}")
    print(f"File: {fpath}")
    print(f"{'='*70}")

    if not os.path.exists(fpath):
        print(f"  FILE NOT FOUND")
        return

    text = open(fpath, 'r', errors='replace').read()
    print(f"  Size: {len(text):,} chars, Lines: {text.count(chr(10))+1}")

    matches = list(re.finditer(r'new\s+Function', text))
    print(f"  new Function() occurrences: {len(matches)}")

    for i, m in enumerate(matches):
        start = max(0, m.start() - 120)
        end = min(len(text), m.end() + 120)
        ctx = text[start:end].replace('\n', ' ')
        print(f"\n  [{i+1}] Offset {m.start()}:")
        print(f"      ...{ctx}...")

        # Check what's passed to new Function
        after = text[m.end():m.end()+200]
        paren_match = re.match(r'\s*\(([^)]*)\)', after)
        if paren_match:
            arg = paren_match.group(1).strip()
            if arg.startswith('"') or arg.startswith("'"):
                print(f"      VERDICT: SAFE - hardcoded string argument: {arg[:80]}")
            elif '+' in arg or 'var' in arg.lower():
                print(f"      VERDICT: POTENTIALLY DANGEROUS - dynamic argument: {arg[:80]}")
            else:
                print(f"      VERDICT: NEEDS REVIEW - argument: {arg[:80]}")

    # Check for message listeners in same file
    msg_patterns = [
        (r'chrome\.runtime\.onMessage', 'chrome.runtime.onMessage'),
        (r'chrome\.runtime\.onMessageExternal', 'chrome.runtime.onMessageExternal'),
        (r'addEventListener\s*\(\s*["\']message', 'addEventListener("message")'),
        (r'onmessage\s*=', 'onmessage handler'),
        (r'postMessage\s*\(', 'postMessage sender'),
    ]
    print(f"\n  Message handling in this file:")
    for pat, name in msg_patterns:
        count = len(re.findall(pat, text))
        if count:
            print(f"    {name}: {count} occurrence(s)")

    # Check for user input sources
    input_patterns = [
        (r'location\.search', 'URL query params'),
        (r'location\.hash', 'URL hash'),
        (r'location\.href', 'location.href'),
        (r'document\.referrer', 'document.referrer'),
        (r'\.value\b', 'input .value reads'),
        (r'URLSearchParams', 'URLSearchParams'),
        (r'fetch\s*\(', 'fetch() calls'),
        (r'XMLHttpRequest', 'XMLHttpRequest'),
    ]
    print(f"\n  User input / external data sources:")
    for pat, name in input_patterns:
        count = len(re.findall(pat, text))
        if count:
            print(f"    {name}: {count} occurrence(s)")


def analyze_csp():
    """Analyze Content Security Policy."""
    print(f"\n{'='*70}")
    print("ANALYZING: CSP (Content Security Policy)")
    print(f"{'='*70}")

    mpath = os.path.join(EXT_ROOT, "manifest.json")
    m = json.load(open(mpath))
    csp = m.get("content_security_policy", {})

    if isinstance(csp, str):
        print(f"  CSP string: {csp}")
    elif isinstance(csp, dict):
        for scope, policy in csp.items():
            print(f"\n  Scope: {scope}")
            print(f"  Policy: {policy}")
            directives = policy.split(';')
            for d in directives:
                d = d.strip()
                if not d:
                    continue
                print(f"    Directive: {d}")
                if "'unsafe-inline'" in d:
                    print(f"      WARNING: unsafe-inline allows inline scripts/styles")
                if "'unsafe-eval'" in d:
                    print(f"      CRITICAL: unsafe-eval allows eval()/new Function()")
                if "'none'" in d:
                    print(f"      GOOD: directive blocks this resource type")
                if "*" in d and "https://*" not in d:
                    print(f"      WARNING: wildcard source")

    # Check if unsafe-eval is present (would make new Function exploitable)
    full_csp = json.dumps(csp)
    if "'unsafe-eval'" in full_csp:
        print("\n  CRITICAL: CSP allows unsafe-eval — new Function() IS exploitable!")
    else:
        print("\n  NOTE: CSP does NOT allow unsafe-eval")
        print("  This means new Function() calls in extension pages may be blocked by CSP")
        print("  However, service workers/background scripts are NOT subject to CSP")


def analyze_permissions():
    """Check if permissions are actually used."""
    print(f"\n{'='*70}")
    print("ANALYZING: Permission Usage")
    print(f"{'='*70}")

    mpath = os.path.join(EXT_ROOT, "manifest.json")
    m = json.load(open(mpath))

    perms = m.get("permissions", [])
    host_perms = m.get("host_permissions", [])
    optional = m.get("optional_permissions", [])

    # API patterns for each permission
    perm_apis = {
        "tabs": r"chrome\.tabs\.",
        "cookies": r"chrome\.cookies\.",
        "webRequest": r"chrome\.webRequest\.",
        "privacy": r"chrome\.privacy\.",
        "scripting": r"chrome\.scripting\.",
        "storage": r"chrome\.storage\.",
        "notifications": r"chrome\.notifications\.",
        "contextMenus": r"chrome\.contextMenus\.",
        "webNavigation": r"chrome\.webNavigation\.",
        "alarms": r"chrome\.alarms\.",
        "offscreen": r"chrome\.offscreen\.",
    }

    # Scan all JS files
    js_files = []
    for root, dirs, files in os.walk(EXT_ROOT):
        for f in files:
            if f.endswith('.js'):
                js_files.append(os.path.join(root, f))

    all_code = ""
    for jf in js_files:
        try:
            all_code += open(jf, 'r', errors='replace').read() + "\n"
        except:
            pass

    print(f"\n  Scanned {len(js_files)} JS files")
    print(f"\n  Permission         | Declared | Used | Verdict")
    print(f"  {'─'*18} | {'─'*8} | {'─'*4} | {'─'*30}")

    for perm in perms:
        api_pat = perm_apis.get(perm)
        if api_pat:
            used = bool(re.search(api_pat, all_code))
            verdict = "OK - in use" if used else "UNUSED - over-privileged?"
            print(f"  {perm:18s} | {'YES':8s} | {'YES' if used else 'NO':4s} | {verdict}")
        else:
            print(f"  {perm:18s} | {'YES':8s} | {'?':4s} | No API pattern to check")

    print(f"\n  Host permissions: {host_perms}")
    if "http://*/*" in host_perms or "https://*/*" in host_perms:
        print("  WARNING: Has access to ALL websites")
        print("  This means content scripts + webRequest can intercept all browsing")

    print(f"\n  Optional permissions: {optional}")


def analyze_externally_connectable():
    """Check external attack surface."""
    print(f"\n{'='*70}")
    print("ANALYZING: External Attack Surface")
    print(f"{'='*70}")

    mpath = os.path.join(EXT_ROOT, "manifest.json")
    m = json.load(open(mpath))

    ec = m.get("externally_connectable")
    if ec:
        print(f"  externally_connectable: {json.dumps(ec, indent=4)}")
        print("  WARNING: External websites can send messages to this extension!")
    else:
        print("  No externally_connectable field")
        print("  External websites CANNOT send runtime messages to this extension")
        print("  This significantly limits the attack surface for new Function()")

    # Check for web_accessible_resources
    war = m.get("web_accessible_resources", [])
    if war:
        print(f"\n  web_accessible_resources:")
        for entry in war:
            print(f"    {json.dumps(entry)}")
    else:
        print(f"\n  No web_accessible_resources — extension files not accessible from web")


def main():
    print("LASTPASS EXTENSION SECURITY VULNERABILITY ANALYSIS")
    print("=" * 70)

    # Finding #8: new Function in 691.691.js
    analyze_new_function(
        os.path.join(EXT_ROOT, "static/js/691.691.js"),
        "Finding #8: new Function() in 691.691.js"
    )

    # Finding #9: new Function in safari-okta
    analyze_new_function(
        os.path.join(EXT_ROOT, "web-client-safari-okta-login-request.js"),
        "Finding #9: new Function() in web-client-safari-okta-login-request.js"
    )

    # Finding #7: CSP
    analyze_csp()

    # Findings #1-6: Permissions
    analyze_permissions()

    # External attack surface
    analyze_externally_connectable()

    # Final verdict
    print(f"\n{'='*70}")
    print("FINAL VERDICT")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
