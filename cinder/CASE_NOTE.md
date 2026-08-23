# Case Note - Operation "Cinder"

Investigators seized a phone from a suspect in a data-leak case. From the device we
extracted the data folder of one chat app, `com.example.cinder`. The suspect is sure the
trail is clean.

Handout contents (`cinder_extract.zip`), laid out exactly like the app sandbox on the
device:

```
com.example.cinder/
  databases/         chat.db, chat.db-wal, chat.db-shm
  shared_prefs/      secure_prefs.xml
  files/             (app data)
```

Recover the conversation and find what was hidden. Work on a copy; keep the originals
intact.

SHA256 (`cinder_extract.zip`): `dfa4e7109fb463a38eeea77903c915cd77b9de99ab261fa4341363a77b9c6b35`
