# Recovery workflow

1. Check WhatsApp's own in-app backup settings and note the last backup date.
2. Scan only folders you can access, such as Android shared media directories.
3. Save a scan snapshot. Repeat later and compare snapshots.
4. Preview accessible media in the local dashboard.
5. Export selected intact media to a separate folder and confirm SHA-256 verification.
6. For chats, follow WhatsApp's official restore flow from a valid backup.

A removed entry in a later scan only means it was not found at that path. It may have moved or become inaccessible. The toolkit does not decrypt `.crypt*` backups, access private app sandboxes, or reconstruct deleted messages from no remaining data.
