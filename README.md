# iso: distributed filesystem for petabytes of data

iso is a simple filesystem built in C. The code here only manages the files, but the fileservers themselfs are nginx instances for added speed and simplicity when deploying. Using nginx means that the code ultimately stays simple and therefore is less prone to bugs.

## Dependencies

The manager uses:

- mongoose: for a embeddable web server
- protobuf: encoding and decoding entries
- leveldb: keeping track of different entries and their locations
