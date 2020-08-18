# zorrent
Experimental Zig torrent library and client example program.

```sh
$ git pull --recurse-submodules
$ zig build
$ ./zig-cache/bin/zorrent zig-bencode/input/OpenBSD_6.6_alpha_install66.iso-2019-10-16-1254.torrent
```

## ROADMAP

- [x] TCP
- [x] Smart piece request based on the bitfield/have peer messages
- [x] Check pieces SHA1 hashes
- [ ] Re-fetch piece if hash fails
- [ ] Request pipelining
- [ ] Support torrent with multiple files
- [ ] Add timeout to expire acquired file offset
- [ ] UDP
- [ ] Extension messages
- [ ] Serve pieces

