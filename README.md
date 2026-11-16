# tenant-verify

SSB Ban Suksomboon — LINE Official Account **@276orarq** tenant verification.

- index.html + config.js: LIFF page (https://liff.line.me/2012636052-SHKZSKR5). Tenants enter room number + registered email, receive a one-time code by email, and the server links their LINE account to the room.
- apps_script/Code.gs: Google Apps Script gateway. Verifies the LINE ID token with LINE, sends the OTP, stores only hashed codes, one LINE account per room, revokes access after check-out.

No secrets, tokens or tenant data are stored in this repository. Secrets live only in the owner's Apps Script *Script properties*.
