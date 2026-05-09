import re, os

EXT = "output/workspace/extension"

print("=" * 70)
print("TESTING WEB-ACCESSIBLE RESOURCES FOR EXPLOITABILITY")
print("=" * 70)

war_files = [
    "webclient-infield.html",
    "webclient-tab-prompt.html",
    "first-password-loggedin-detector.js",
    "extension-pendo.html",
]

for wf in war_files:
    for root, dirs, files in os.walk(EXT):
        if wf in files:
            fpath = os.path.join(root, wf)
            text = open(fpath, 'r', errors='replace').read()
            print(f"\n--- {wf} ({len(text)} chars) ---")
            dangerous = {
                'innerHTML': len(re.findall(r'innerHTML\s*=', text)),
                'eval(': len(re.findall(r'\beval\s*\(', text)),
                'new Function': len(re.findall(r'new\s+Function', text)),
                'document.write': len(re.findall(r'document\.write\s*\(', text)),
                'postMessage': len(re.findall(r'postMessage\s*\(', text)),
                'onmessage': len(re.findall(r'onmessage|addEventListener.*message', text)),
                'location.href': len(re.findall(r'location\.href', text)),
                'URL params': len(re.findall(r'location\.search|URLSearchParams', text)),
            }
            for sink, count in dangerous.items():
                if count:
                    print(f"  FOUND: {sink} x{count}")
            if not any(dangerous.values()):
                print(f"  No dangerous sinks found")
            break

print(f"\n{'='*70}")
print("CHECKING: Can content scripts be hijacked via postMessage?")
print(f"{'='*70}")

cs_file = os.path.join(EXT, "web-client-content-script.js")
if os.path.exists(cs_file):
    text = open(cs_file, 'r', errors='replace').read()
    print(f"Content script: {len(text)} chars")
    msg_handlers = list(re.finditer(r"addEventListener\s*\(\s*[\"']message", text))
    print(f"  addEventListener('message'): {len(msg_handlers)}")
    origin_checks = list(re.finditer(r"\.origin\s*[!=]==?\s*[\"']", text))
    print(f"  Origin validation checks: {len(origin_checks)}")
    if msg_handlers and not origin_checks:
        print("  WARNING: Message handlers WITHOUT origin validation!")
    elif msg_handlers and origin_checks:
        print("  OK: Message handlers have origin validation")

print(f"\n{'='*70}")
print("CHECKING: notifications and alarms usage (flagged as unused)")
print(f"{'='*70}")
for root, dirs, files in os.walk(EXT):
    for f in files:
        if f.endswith('.js'):
            fpath = os.path.join(root, f)
            text = open(fpath, 'r', errors='replace').read()
            if 'chrome.notifications' in text:
                print(f"  chrome.notifications FOUND in {f}")
            if 'chrome.alarms' in text:
                print(f"  chrome.alarms FOUND in {f}")
