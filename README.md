# keycloak-ldap-password-hash

Keycloak password hash provider for password hashes taken over from an LDAP directory. It lets users
imported from LDAP log in with their existing passwords.

The provider id is `ssha`. Supported hash formats (prefix is case-insensitive):

| Prefix | Algorithm |
|---|---|
| `{SHA}`, `{SSHA}` | SHA-1, unsalted / salted |
| `{SHA256}`, `{SSHA256}` | SHA-256, unsalted / salted |
| `{SHA384}`, `{SSHA384}` | SHA-384, unsalted / salted |
| `{SHA512}`, `{SSHA512}` | SHA-512, unsalted / salted |

Salted values are `base64(digest(password + salt) + salt)`. Other prefixes (e.g. `{MD5}`, `{PBKDF2...}`)
are rejected with an error in the Keycloak log, and the login fails.

## Re-hashing on login

Keycloak decides on every login, using the realm's hash algorithm, whether the stored hash is replaced:

- **Realm default** (no `hashAlgorithm` in the password policy): the first login replaces the LDAP hash
  with the realm's algorithm (argon2).
- **`hashAlgorithm(ssha)`**: stored hashes are never changed on login. Use this while passwords are synced
  from LDAP, otherwise every user who logs in looks changed to the sync. Passwords set in Keycloak are
  stored as `{SSHA512}`. Removing the setting after the transition switches back to re-hashing.

`hashAlgorithm(ssha)` is a rule of the realm's password policy (admin console: Authentication → Policies →
Password policy → Hashing Algorithm). Via REST or `kcadm.sh` the `passwordPolicy` string replaces the whole
policy, so existing rules have to be included, e.g. `length(12) and hashAlgorithm(ssha)`.

## Compatibility

Built and tested against Keycloak 26.8.1 (`keycloak.version` in `pom.xml`). The project has its own
version; the password hash SPI has been unchanged since Keycloak 26.0. For a new Keycloak version, raise
`keycloak.version` and run the integration tests. Requires Java 21.

## Build and tests

```bash
mvn clean package   # build + unit tests
mvn verify          # additionally the integration tests (*IT) against a real Keycloak server
```

The integration tests use the Keycloak test framework, which downloads and starts the Keycloak
distribution of `keycloak.version`. They import users with LDAP hashes, log in with the password grant
and check the stored hash afterwards, with and without `hashAlgorithm(ssha)`.

## Release

`git release patch|minor|major` (the first one: `git release 1.0.0`) pushes the tag `X.Y.Z`. The GitHub
workflow builds the tag as version `X.Y.Z`, runs all tests and attaches the jar to the GitHub release.
Local builds without `-Drevision` get the version `dev-SNAPSHOT`.

## Installation

Copy the jar from the GitHub release into the `providers/` directory of the Keycloak installation and run
`kc.sh build`. The jar has no dependencies besides Keycloak.

## Usage

Import users with the hash as stored in LDAP and the algorithm `ssha`, for example via the Admin REST API
or a realm import:

```json
{
  "username": "jdoe",
  "credentials": [
    {
      "type": "password",
      "secretData": "{\"value\":\"{SSHA512}0BUE16yD4/wzbY+yHR/x3gWFp99xfY+dwVuAmsmrU2hGs1A/xarhzIgNlI0gV4gIJoDdmFqaKfnMl3reuEhbBAECAwQFBgcI\"}",
      "credentialData": "{\"hashIterations\":-1,\"algorithm\":\"ssha\"}"
    }
  ]
}
```

The import should check the prefixes against the table above and stop on unknown ones; otherwise the
problem only shows up as failed logins.

## Removing the provider

Users who never log in keep their LDAP hash. Only remove the jar once no password credential uses the
algorithm `ssha` any more, otherwise those users can no longer log in, and Keycloak logs this only at
DEBUG level:

```sql
select count(*) from credential where type = 'password' and credential_data like '%"algorithm":"ssha"%';
```
