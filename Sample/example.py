from checksumlib import FileChecksum



sha1 = FileChecksum(algorithm="sha1")
print(sha1.verify_checksum("test.txt", sha1.create_checksum("test.txt").hexdigest()))
print(sha1.verify_checksum("test.txt", sha1.create_checksum("test.txt").digest()))
print(sha1.verify_checksum("test.txt", sha1.create_checksum("test.txt")))

sha224 = FileChecksum(algorithm="sha224")
print(sha224.verify_checksum("test.txt", sha224.create_checksum("test.txt").hexdigest()))
print(sha224.verify_checksum("test.txt", sha224.create_checksum("test.txt").digest()))
print(sha224.verify_checksum("test.txt", sha224.create_checksum("test.txt")))

sha256 = FileChecksum(algorithm="sha256")
print(sha256.verify_checksum("test.txt", sha256.create_checksum("test.txt").hexdigest()))
print(sha256.verify_checksum("test.txt", sha256.create_checksum("test.txt").digest()))
print(sha256.verify_checksum("test.txt", sha256.create_checksum("test.txt")))

sha384 = FileChecksum(algorithm="sha384")
print(sha384.verify_checksum("test.txt", sha384.create_checksum("test.txt").hexdigest()))
print(sha384.verify_checksum("test.txt", sha384.create_checksum("test.txt").digest()))
print(sha384.verify_checksum("test.txt", sha384.create_checksum("test.txt")))

sha512 = FileChecksum(algorithm="sha512")
print(sha512.verify_checksum("test.txt", sha512.create_checksum("test.txt").hexdigest()))
print(sha512.verify_checksum("test.txt", sha512.create_checksum("test.txt").digest()))
print(sha512.verify_checksum("test.txt", sha512.create_checksum("test.txt")))


sha3_224 = FileChecksum(algorithm="sha3_224")
print(sha3_224.verify_checksum("test.txt", sha3_224.create_checksum("test.txt").hexdigest()))
print(sha3_224.verify_checksum("test.txt", sha3_224.create_checksum("test.txt").digest()))
print(sha3_224.verify_checksum("test.txt", sha3_224.create_checksum("test.txt")))

sha3_256 = FileChecksum(algorithm="sha3_256")
print(sha3_256.verify_checksum("test.txt", sha3_256.create_checksum("test.txt").hexdigest()))
print(sha3_256.verify_checksum("test.txt", sha3_256.create_checksum("test.txt").digest()))
print(sha3_256.verify_checksum("test.txt", sha3_256.create_checksum("test.txt")))

sha3_384 = FileChecksum(algorithm="sha3_384")
print(sha3_384.verify_checksum("test.txt", sha3_384.create_checksum("test.txt").hexdigest()))
print(sha3_384.verify_checksum("test.txt", sha3_384.create_checksum("test.txt").digest()))
print(sha3_384.verify_checksum("test.txt", sha3_384.create_checksum("test.txt")))

sha3_512 = FileChecksum(algorithm="sha3_512")
print(sha3_512.verify_checksum("test.txt", sha3_512.create_checksum("test.txt").hexdigest()))
print(sha3_512.verify_checksum("test.txt", sha3_512.create_checksum("test.txt").digest()))
print(sha3_512.verify_checksum("test.txt", sha3_512.create_checksum("test.txt")))


shake_128 = FileChecksum(algorithm="shake_128")
print(shake_128.verify_checksum("test.txt", shake_128.create_checksum("test.txt").hexdigest(32), length=32))
print(shake_128.verify_checksum("test.txt", shake_128.create_checksum("test.txt").digest(32), length=32))
print(shake_128.verify_checksum("test.txt", shake_128.create_checksum("test.txt"), length=32))

shake_256 = FileChecksum(algorithm="shake_256")
print(shake_256.verify_checksum("test.txt", shake_256.create_checksum("test.txt").hexdigest(32), length=32))
print(shake_256.verify_checksum("test.txt", shake_256.create_checksum("test.txt").digest(32), length=32))
print(shake_256.verify_checksum("test.txt", shake_256.create_checksum("test.txt"), length=32))


blake2s = FileChecksum(algorithm="blake2s")
print(blake2s.verify_checksum("test.txt", blake2s.create_checksum("test.txt").hexdigest()))
print(blake2s.verify_checksum("test.txt", blake2s.create_checksum("test.txt").digest()))
print(blake2s.verify_checksum("test.txt", blake2s.create_checksum("test.txt")))

blake2b = FileChecksum(algorithm="blake2b")
print(blake2b.verify_checksum("test.txt", blake2b.create_checksum("test.txt").hexdigest()))
print(blake2b.verify_checksum("test.txt", blake2b.create_checksum("test.txt").digest()))
print(blake2b.verify_checksum("test.txt", blake2b.create_checksum("test.txt")))


md5 = FileChecksum(algorithm="md5")
print(md5.verify_checksum("test.txt", md5.create_checksum("test.txt").hexdigest()))
print(md5.verify_checksum("test.txt", md5.create_checksum("test.txt").digest()))
print(md5.verify_checksum("test.txt", md5.create_checksum("test.txt")))


# Open SSL

sha512_224 = FileChecksum(algorithm="sha512_224")
print(sha512_224.verify_checksum("test.txt", sha512_224.create_checksum("test.txt").hexdigest()))
print(sha512_224.verify_checksum("test.txt", sha512_224.create_checksum("test.txt").digest()))
print(sha512_224.verify_checksum("test.txt", sha512_224.create_checksum("test.txt")))


sha512_256 = FileChecksum(algorithm="sha512_256")
print(sha512_256.verify_checksum("test.txt", sha512_256.create_checksum("test.txt").hexdigest()))
print(sha512_256.verify_checksum("test.txt", sha512_256.create_checksum("test.txt").digest()))
print(sha512_256.verify_checksum("test.txt", sha512_256.create_checksum("test.txt")))


md5_sha1 = FileChecksum(algorithm="md5-sha1")
print(md5_sha1.verify_checksum("test.txt", md5_sha1.create_checksum("test.txt").hexdigest()))
print(md5_sha1.verify_checksum("test.txt", md5_sha1.create_checksum("test.txt").digest()))
print(md5_sha1.verify_checksum("test.txt", md5_sha1.create_checksum("test.txt")))


md4 = FileChecksum(algorithm="md4")
print(md4.verify_checksum("test.txt", md4.create_checksum("test.txt").hexdigest()))
print(md4.verify_checksum("test.txt", md4.create_checksum("test.txt").digest()))
print(md4.verify_checksum("test.txt", md4.create_checksum("test.txt")))


sm3 = FileChecksum(algorithm="sm3")
print(sm3.verify_checksum("test.txt", sm3.create_checksum("test.txt").hexdigest()))
print(sm3.verify_checksum("test.txt", sm3.create_checksum("test.txt").digest()))
print(sm3.verify_checksum("test.txt", sm3.create_checksum("test.txt")))


mdc2 = FileChecksum(algorithm="mdc2")
print(mdc2.verify_checksum("test.txt", mdc2.create_checksum("test.txt").hexdigest()))
print(mdc2.verify_checksum("test.txt", mdc2.create_checksum("test.txt").digest()))
print(mdc2.verify_checksum("test.txt", mdc2.create_checksum("test.txt")))


ripemd160 = FileChecksum(algorithm="ripemd160")
print(ripemd160.verify_checksum("test.txt", ripemd160.create_checksum("test.txt").hexdigest()))
print(ripemd160.verify_checksum("test.txt", ripemd160.create_checksum("test.txt").digest()))
print(ripemd160.verify_checksum("test.txt", ripemd160.create_checksum("test.txt")))


whirlpool = FileChecksum(algorithm="whirlpool")
print(whirlpool.verify_checksum("test.txt", whirlpool.create_checksum("test.txt").hexdigest()))
print(whirlpool.verify_checksum("test.txt", whirlpool.create_checksum("test.txt").digest()))
print(whirlpool.verify_checksum("test.txt", whirlpool.create_checksum("test.txt")))
