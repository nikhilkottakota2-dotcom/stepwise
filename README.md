# Stepwise

Stepwise is a local web app for DSA problem solving and algorithm practice. Accounts require email verification; the sign-in screen supports password reset by email.

## Run it

1. Install Python 3.10 or newer if it is not already installed.
2. From this folder, run `./start_stepwise.ps1`. It asks for your Gmail app password without saving it to a file.
3. Open http://127.0.0.1:8000 in your browser.
4. Select **Sign in → Create account** to make an account.

The server uses only Python's standard library. It creates `data/loop.sqlite3` on first start. Email verification links expire after 24 hours; password reset links expire after one hour. Tokens are stored hashed, can be used once, and password resets revoke existing sessions.

## Configure email

The Windows launcher configures Gmail SMTP for the current server process. It prompts for the app password securely; the password is never written into this project. The server also accepts SMTP environment variables if you use a different provider:

```powershell
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "your-mailbox@example.com"
$env:SMTP_PASSWORD = "your-smtp-password"
$env:SMTP_FROM = "Stepwise <your-mailbox@example.com>"
$env:APP_BASE_URL = "http://127.0.0.1:8000"
python server.py
```

Use port 587 with STARTTLS or port 465 with implicit TLS. `APP_BASE_URL` must be the address recipients can open from their device. Without SMTP settings, account creation can be started but verification/reset emails cannot be delivered; the app shows a setup message.

**Before publishing:** replace the current personal sender address with a production sender, update `APP_BASE_URL` to the deployed HTTPS domain, and create a new provider credential for deployment. Do not publish the app password supplied for local use.
Accounts store a name, email, a salted PBKDF2 password hash, and language preference (JavaScript, Python, Java, C, or C++). The algorithm practice catalog is grouped by beginner, intermediate, and advanced levels. Guided algorithm completions and the six starter problem set issue printable certificates. Practice sessions use random, HttpOnly, SameSite cookies; solved problems are stored per account. The database file stays on this computer unless you move it.

This is a local prototype. Before public deployment, move it behind HTTPS, set up backups and monitoring, and verify the production mail configuration.



Problem and algorithm-practice tests run JavaScript in an isolated, time-limited browser frame. The six starter problems and the full algorithm-practice catalog also have Python and Java test runners when Python and a JDK are installed. C and C++ templates remain available, but test execution is not configured; it needs compiler detection plus C/C++ harnesses. Progress is saved only after the selected runner reports that all cases pass.

Python and Java source is executed by the local server with a short timeout. Keep this prototype bound to localhost and do not expose its execution endpoint to the public internet; there is no production-grade code sandbox.

