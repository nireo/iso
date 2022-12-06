# iso: distributed filesystem for petabytes of data

iso is a simple filesystem built in C. The code here only manages the files, but the fileservers themselfs are nginx instances for added speed and simplicity when deploying. Using nginx means that the code ultimately stays simple and therefore is less prone to bugs.

## Dependencies

The manager uses:

- mongoose: for a embeddable web server
- leveldb: keeping track of different entries and their locations

## TODO:

- Stop using OpenSSL functions and custom base64 implementation when mongoose has its own functions for both things.
- Replication to multiple volumes, currently file is written to a "randomly" chosen volume.
