# gdfind - Golang duplicate find

Did the world really need yet another duplicate finder? Probably not, but neither was I able to find any that suited my purposes.

The one that came closest is the excellent [rdfind](https://github.com/pauldreik/rdfind), but it is frustratingly opaque about it's progress, the read buffer isn't configurable, and the result file leaves something to be desired. It's still magnitudes faster than most duplicate finders (which usually naively checksum all files), and has packages in most distros, so check it out.

### Differences from rdfind
- Golang instead of C (obviously)
- Progress bars during IO activity
- More (optional) realtime logging, most importantly progress bars during hashing
- Always scans deterministically, a limitation of `filepath.WalkDir`
- Only supports CRC64 checksumming currently. This can sound scary to anyone used to working with cryptographic hashes like sha256, but aside from the [inherently miniscule probability](http://apollo.backplane.com/matt/crc64.html) of a collision given the large space, the chances of such a collision slipping past the size, head hash and tail hash checks is even lower. I suppose a determined adversary could generate one, but at that point the TOCTOU problems are probably a bigger concern.
- Only supports hardlinking at the moment
