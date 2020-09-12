# zorrent
Experimental Zig torrent library and client example program.

    $ git pull --recurse-submodules https://github.com/gaultier/zorrent.git
    # Requires libcurl
    $ zig build
    $ ./zig-cache/bin/zorrent zig-bencode/input/OpenBSD_6.6_alpha_install66.iso-2019-10-16-1254.torrent
    OpenBSD_6.6_alpha_install66.iso [1043/1043 260.70MiB/260.70MiB] 100.00%

    # Run all tests
    $ zig build test

## ROADMAP

- BEP-0003:
  * [x] Download one file
  * [x] Smart piece request based on the bitfield/have peer messages
  * [x] Check pieces SHA1 hashes
  * [x] Re-fetch piece if hash fails
  * [x] Request pipelining
  * [x] Support torrent with multiple files
  * [ ] Upload files (serve)
  * [x] Save want state to continue downloading a file after a restart
  * [x] Check hashes in parallel
  * [ ] Get peers from trackers in parallel
  * [ ] Pick up new peers while downloading from other peers
  * [x] Retry connecting to peers when disconnected
- [x] Multi-tracker (BEP-0012)
- [x] Compact peer list from tracker (BEP-0023)
- [ ] Better download algorithm: get rarest pieces first
- [ ] Fast extension (BEP-0006)
- [ ] UDP
- [ ] Extension messages

