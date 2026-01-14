# Password Strength Web App

Local educational tool. Don’t enter real passwords.

## Overview
- Defensive-only password evaluation (no cracking or brute force).
- zxcvbn scoring plus extra rules (length, variety, repeats, sequences, keyboard patterns).
- Optional common-password and breached-password checks.

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
export HIBP_ENABLED=false
export ROCKYOU_PATH=./data/rockyou.txt
flask --app app run --host 127.0.0.1 --port 5000
```
Then open http://127.0.0.1:5000.

## Tests
```bash
pytest
```

To enable the breached-password check (k-anonymity), set:
```bash
export HIBP_ENABLED=true
```

## Common Password List (RockYou)
The app reads RockYou from `ROCKYOU_PATH` (default: `data/rockyou.txt`) and loads it into memory for defensive common-password checks only.

Download RockYou from a public SecLists mirror or Kali wordlists (do not bundle it in the repo):
```bash
# SecLists mirror
curl -L -o data/rockyou.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt

# Kali (if installed locally)
cp /usr/share/wordlists/rockyou.txt data/rockyou.txt
```

Memory note: RockYou contains millions of entries and can take hundreds of MB of RAM when loaded as a Python `set`. Use a smaller list if memory is constrained.

## Security Notes
- Passwords are processed in memory only.
- The API never logs or stores raw passwords.
- Rate limiting is enabled on `/check`.
- Requests larger than 2KB are rejected.

## Defensive Scope
This project is intentionally defensive: it evaluates password strength and checks against public breach/common lists. It does **not** attempt to guess, crack, or brute-force passwords.
