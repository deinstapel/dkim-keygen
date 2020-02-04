# dkim-keygen

This project aims to create a sidecar container running along with the https://github.com/tomav/docker-mailserver image to automatically create, manage and deploy DKIM keys when the mailserver image is deployed in an LDAP enabled configuration.

## How it works

This program polls the LDAP server for mail accounts and extracts all used mail domains.

e.g. if your LDAP server contains mail accounts for info@example.com and fw@examp.le, both example.com and examp.le will be generated domain keys for.

After the collection of all mail domains is finished, a DKIM key pair will be loaded or created per domain and written into the target directory.

After this has finished, the program generates both an OpenDKIM KeyTable and SigningTable. Furthermore, it updates DNS Records at Cloudflare using the API to reflect the current public key.

Finally, a running OpenDKIM process is sent a SIGUSR1 to initiate a config reload.

## Configuration

This program is configured via environment variables.
All variables must be prefixed with `DKIM_KEYGEN_`.

| Variable | Meaning | Example |
| -------- | ------- | ------- |
| DEBUG    | Enables verbose logging | `true`
| LDAP_SERVER | LDAP Server address to query | `ldap://localhost:389`
| LDAP_BIND_USER | LDAP Bind DN | `uid=svc,dc=example,dc=com`
| LDAP_BIND_PASS | LDAP Bind Password | `passw0rd`
| LDAP_USER_BASE_DN | LDAP Base DN to search for user/mail accounts | `ou=users,dc=example,dc=com`
| LDAP_USER_FILTER | LDAP Filter to identify valid users | `(objectClass=mailAccount)`
| LDAP_MAIL_ATTRIBUTES | A space separated list of attributes to fetch, used to include mail lists | `email mailalias mailGroupMember`
| LDAP_SYNC_INTERVAL | The interval between two LDAP Synchronizations | `5m`
| TARGET_PATH | Path where the OpenDKIM config resides. The generated keys will be deployed to this path. | `/etc/opendkim`
| CF_API_KEY | Cloudflare API Key used to update the TXT Records. | `s9bved9bvf-wbdsvosidbvfosidbv` (No, this is not a valid CF Key, don't even try it.)
