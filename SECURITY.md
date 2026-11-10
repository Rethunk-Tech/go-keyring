# Security

## Supported versions

The latest tagged release. There are no long-lived release branches, so a fix ships in the next tag
rather than being backported.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/Totative/go-keyring/security/advisories/new)
on this repository (Security → Report a vulnerability). It stays private until a fix ships.
The organisation's [security policy](https://github.com/Totative/.github/blob/main/SECURITY.md)
covers the rest, safe harbour included.

Please do not open a public issue for a suspected vulnerability first.

## What is in scope

- The sealed file (`secrets`) and the plain file (`secrets.json`) in the store folder. Another process in the sandbox can write them. A malformed or foreign sealed file must give an error, never a panic, a partial store or a changed file; GCM rejects any altered ciphertext. A malformed plain file must give an error and stay in place. `FuzzUnseal` and `FuzzPlainFile` cover both.
- The store folder. A symlink or a folder owned by another user is refused, and an open mode is tightened to `0700`. Files are written `0600` through an atomic rename. `Folder` is validated as one path element so it cannot leave the data home.
- Item names and values, passed to the backend verbatim. They are never logged or put in an error text.
- Reads from the host Secret Service. A locked, dismissed or absent host is a miss, not a reason to write secrets in plain text.

## What is out of scope

- The caller chooses `Service`, `SealInfo` and `Folder`, and keeps them stable.
- The OS keyring, the XDG Secret portal and the host Secret Service are trusted. A process running as the same user outside the sandbox can read the keyring by design.
- The plain `0600` file is unencrypted on purpose, when neither the portal nor a host keyring exists. `Plaintext` reports it so the app can warn the user.
- A process with the same user's access to the data folder can delete the store. That is availability, not confidentiality.
