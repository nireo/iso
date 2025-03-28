# iso: distributed filesystem in c

Iso is a relatively simple distributed file system. The storage nodes handle HTTP post requests and store and retrieve files. The main dependencies are leveldb for fast retrieval of file metadata and libdill to provide structured concurrency. Mainly decided to use libdill since I like the golang way of doing concurrency and that is pretty close and it's also very performant.
