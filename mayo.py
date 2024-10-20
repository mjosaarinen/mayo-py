#   mayo.py
#   2024-10-20  Markku-Juhani O. Saarinen <mjos@iki.fi>. See LICENSE

#   === Mayo 1.0

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256

class Mayo:

    #   initialize
    def __init__(self,  n=66, m=64, o=8, k=9, salt_sz=24, digest_sz=32,
                        tail_f=[8, 0, 2, 8, 0], alg_id='MAYO_1',
                        rbg=None):
        self.n          =   n
        self.m          =   m
        self.o          =   o
        self.k          =   k
        self.salt_sz    =   salt_sz
        self.tail_f     =   tail_f
        self.hash_sz    =   digest_sz
        self.katname    =   alg_id
        #   derived parameters
        self.seed_pk_sz =   16
        self.seed_sk_sz =   self.salt_sz
        self.v          =   self.n - self.o
        self.o_sz       =   (self.v * self.o + 1) // 2
        self.v_sz       =   (self.v + 1) // 2
        self.p1_sz      =   (self.m * (self.v + 1) * self.v // 2) // 2
        self.p2_sz      =   (self.m * self.v * self.o) // 2
        self.p3_sz      =   (self.m * self.o * (self.o + 1) // 2) // 2
        self.sk_sz      =   self.seed_sk_sz
        self.pk_sz      =   self.seed_pk_sz + self.p3_sz
        self.epk_sz     =   self.p1_sz + self.p2_sz + self.p3_sz
        self.sig_sz     =   (self.n * self.k + 1) // 2 + self.salt_sz

        #   multiplication tables
        self.GF16_INV = bytearray(16)
        self.GF16_MUL = [ bytearray(16) for _ in range(16) ]
        for x in range(16):
            for y in range(16):
                z = self.gf16_mul(x, y)
                self.GF16_MUL[x][y] = z
                if z == 1:
                    self.GF16_INV[x] = y

    #   === Utility Functions

    def set_random(self, rbg):
        """ Set the key material RBG."""
        self.rbg        =   rbg

    def shake256(self, x, l):
        """ shake256s(x, l): Internal hook."""
        return SHAKE256.new(x).read(l)

    def aes128ctr(self, key, l, ctr=0):
        """ aes128ctr(key, l): Internal hook."""
        iv      =   b'\x00' * 12
        aesctr  =   AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=ctr)
        return  aesctr.encrypt(b'\x00' * l)

    def decode_vec(self, n, bs):
        """ 2.1.4.4 Byte-string to vector: Decodevec (n, bytestring)."""
        v = bytearray(n)
        for i in range(0, n - 1, 2):
            x = bs[i // 2]
            v[i] = x & 0xF
            v[i + 1] = x >> 4
        if n % 2 == 1:
            v[n - 1] = bs[n // 2] & 0xF
        return v

    def encode_vec(self, v):
        n   = len(v)
        bs  = bytearray((n + 1) // 2)
        for i in range(0, n - 1, 2):
            bs[i // 2] = v[i] + (v[i + 1] << 4)
        if n % 2 == 1:
            bs[n // 2] = v[n - 1]
        return bs

    def bs_split4(self, bs, m):
        mlb =   4 * m // 32
        return  [ int.from_bytes(bs[i : i + mlb], byteorder='little')
                    for i in range(0, 4 * mlb, mlb) ]

    def bs_split4_vec(self, bs, m):
        ml4 =   4 * 4 * m // 32
        return  [ self.bs_split4(bs[i : i + ml4], m)
                    for i in range(0, len(bs), ml4) ]

    def bs_mul_add(self, r, a, c):
        """ Bitsliced r += a * c """
        if c & 1:
            r[0]    ^=  a[0]
            r[1]    ^=  a[1]
            r[2]    ^=  a[2]
            r[3]    ^=  a[3]
        if c & 2:
            r[0]    ^=  a[3]
            r[1]    ^=  a[0] ^ a[3]
            r[2]    ^=  a[1]
            r[3]    ^=  a[2]
        if c & 4:
            r[0]    ^=  a[2]
            r[1]    ^=  a[3] ^ a[2]
            r[2]    ^=  a[0] ^ a[3]
            r[3]    ^=  a[1]
        if c & 8:
            r[0]    ^=  a[1]
            r[1]    ^=  a[2] ^ a[1]
            r[2]    ^=  a[3] ^ a[2]
            r[3]    ^=  a[0] ^ a[3]

    def gf16_mul(self, a, b):
        """ Finite field multiplication (a * b) in GF(16). """
        r = 0
        if b & 1:
            r   ^=  a
        if b & 2:
            r   ^=  (a << 1) ^ (a >> 3) ^ ((a >> 2) & 0x2)
        if b & 4:
            r   ^=  (a << 2) ^ (a >> 2) ^ ((a >> 1) & 0x6)
        if b & 8:
            r   ^=  (a << 3) ^ (a >> 1) ^ (a & 0xE)
        return r & 0xF

    def f_mul(self, a, b):
        return self.GF16_MUL[a][b]

    def f_inv(self, a):
        """ Finite field inversion (1/a) in GF(16). """
        return self.GF16_INV[a]

    def bs_add(self, r, a):
        r[0]    ^=  a[0]
        r[1]    ^=  a[1]
        r[2]    ^=  a[2]
        r[3]    ^=  a[3]

    def bs_nibbles(self, a, m):
        return [ (((a[0] >> i) & 1) |
                 (((a[1] >> i) & 1) << 1) |
                 (((a[2] >> i) & 1) << 2) |
                 (((a[3] >> i) & 1) << 3)) for i in range(m) ]

    def bs_bytes(self, a, m):
        bs = b''
        for x in a:
            bs += x.to_bytes(m // 8, byteorder='little')
        return bs

    def bs_shift4(self, a, l):
        return  [ a[0] << l, a[1] << l, a[2] << l, a[3] << l ]

    #   === Key Generation

    def keygen(self, seed_sk = None):
        """ MAYO.CompactKeyGen() """

        if seed_sk == None:
            seed_sk = self.rbg(self.seed_sk_sz)

        #   Derive seed_pk and O from seed_sk
        s       = self.shake256(seed_sk, self.seed_pk_sz + self.o_sz)
        seed_pk = s[0:self.seed_pk_sz]
        oo      = self.decode_vec( self.v * self.o,
                                s[self.seed_pk_sz:self.seed_pk_sz + self.o_sz] )
        om  = []
        for i in range(self.v):
            om  += [ oo[i*self.o : (i+1)*self.o] ]

        #   Derive the P1 and P2 from seed_pk
        epk = self.aes128ctr(seed_pk[0:self.seed_pk_sz], self.p1_sz + self.p2_sz)
        p1v = self.bs_split4_vec( epk[0 : self.p1_sz], self.m )
        p2v = self.bs_split4_vec( epk[self.p1_sz : self.p1_sz + self.p2_sz],
                                    self.m )

        p1i =   0
        p1m =   [ [ [0,0,0,0] for _ in range(self.v) ]
                                for _ in range(self.v) ]
        for r in range(self.v):
            for c in range(r, self.v):
                p1m[r][c] = p1v[p1i]
                p1i += 1

        p2i =   0
        p2m =   [ [ [0,0,0,0] for _ in range(self.o) ]
                                for _ in range(self.v) ]
        for r in range(self.v):
            for c in range(self.o):
                p2m[r][c] = p2v[p2i]
                p2i += 1

        #   compute P1*O + P2
        p1o_p2  =   p2m             # ovewrites p2m
        for r in range(self.v):
            for c in range(r, self.v):
                for j in range(self.o):
                    self.bs_mul_add( p1o_p2[r][j], p1m[r][c], om[c][j] )

        #   compute P3 = O^t * (P1*O + P2)
        p3m =   [ [ [0,0,0,0] for _ in range(self.o) ]
                                for _ in range(self.o) ]
        for r in range(self.o):
            for c in range(self.v):
                for j in range(self.o):
                    self.bs_mul_add( p3m[r][j], p1o_p2[c][j], om[c][r] )

        #   fold P3 into upper triangular & serialize
        cpk = seed_pk
        for r in range(self.o):
            cpk += self.bs_bytes( p3m[r][r], self.m )
            for c in range(r + 1, self.o):
                self.bs_add( p3m[r][c], p3m[c][r] )
                cpk += self.bs_bytes( p3m[r][c], self.m )

        #   secret key
        csk = seed_sk

        return (cpk, csk)

    #   === Create a signature

    def echelon_form(self, bm):
        h = len(bm)
        w = len(bm[0])
        c = 0
        r = 0
        while r < h and c < w:
            i = r
            while i < h and bm[i][c] == 0:
                i += 1
            if i >= h:
                c += 1
                continue
            if i != r:
                for j in range(c, w):
                    bm[r][j] ^= bm[i][j]
                #(bm[r], bm[i]) = (bm[i], bm[r])
            x = self.f_inv(bm[r][c])
            for j in range(c, w):
                bm[r][j] = self.gf16_mul(bm[r][j], x)
            for i in range(r + 1, h):
                x = bm[i][c]
                for j in range(c, w):
                    bm[i][j] ^= self.gf16_mul(bm[r][j], x)
            r += 1
            c += 1

    def sample_solution(self, am, y, rr):
        ko      = self.k * self.o

        #   x <- r
        x   =   rr.copy()

        #   compute y - Ar, put it in the last column of A
        for r in range(self.m):
            t = y[r]
            for i in range(ko):
                t ^= self.gf16_mul(am[r][i], rr[i])
            am[r][ko] = t

        #   Put (Ay) in echelon form with leading 1’s
        self.echelon_form(am)

        #   Check if A has rank m
        t   = 0
        for i in range(ko):
            t |= am[self.m - 1][i]
        if t == 0:
            return None

        #   Back-substitution
        for r in range(self.m - 1, -1, -1):
            for c in range(r, ko):
                if am[r][c] != 0:
                    u = am[r][ko]
                    x[c] ^= u
                    for i in range(r):
                        am[i][ko] ^= self.f_mul(am[i][c], u)
                    break
        return x

    def signature(self, csk, msg, rnd = None):
        """ MAYO.Sign() """

        #   randomize
        if  rnd == None:
            rnd = self.rbg(self.salt_sz)

        #   decode esk
        seed_sk = csk[0:self.seed_sk_sz]

        #   Derive seed_pk and O from seed_sk
        s       = self.shake256(seed_sk, self.seed_pk_sz + self.o_sz)
        seed_pk = s[0 : self.seed_pk_sz]
        oo      = self.decode_vec( self.v * self.o,
                    s[self.seed_pk_sz : self.seed_pk_sz + self.o_sz] )
        om  = []
        for i in range(self.v):
            om  += [ oo[i*self.o : (i+1)*self.o] ]

        #   Derive the P1 and P2 from seed_pk
        epk = self.aes128ctr( seed_pk[0:self.seed_pk_sz],
                                self.p1_sz + self.p2_sz )
        p1v = self.bs_split4_vec( epk[0 : self.p1_sz], self.m )
        p2v = self.bs_split4_vec(
                epk[self.p1_sz : self.p1_sz + self.p2_sz], self.m )

        p1i =   0
        p1m =   [ [ [0,0,0,0] for _ in range(self.v) ]
                                for _ in range(self.v) ]
        for r in range(self.v):
            for c in range(r, self.v):
                p1m[r][c] = p1v[p1i]
                p1i += 1

        p2i =   0
        p2m =   [ [ [0,0,0,0] for _ in range(self.o) ]
                                for _ in range(self.v) ]
        for r in range(self.v):
            for c in range(self.o):
                p2m[r][c] = p2v[p2i]
                p2i += 1

        #   ptm <- P1 + P1^T
        ptm =   [ [ [0,0,0,0] for _ in range(self.v) ]
                                for _ in range(self.v) ]
        for r in range(self.v):
            for c in range(r + 1, self.v):
                ptm[r][c] = p1m[r][c].copy()
                ptm[c][r] = p1m[r][c].copy()

        #   L = (P1 + P1^T)*O + P2
        lm  =   p2m
        for r in range(self.v):
            for c in range(self.v):
                for j in range(self.o):
                    self.bs_mul_add( lm[r][j], ptm[r][c], om[c][j] )

        #   Hash message and derive salt and t
        m_hash  = self.shake256(msg, self.hash_sz)
        salt    = self.shake256(m_hash + rnd + seed_sk, self.salt_sz)

        mt      = self.decode_vec( self.m,
                    self.shake256(m_hash + salt, (self.m + 1) // 2) )

        #   Attempt to find a preimage for t
        for ctr in range(256):

            vbs = self.shake256( m_hash + salt + seed_sk + bytes([ctr]),
                            self.k * self.v_sz + ((self.k * self.o + 1) // 2) )

            #   Derive vi and r
            vm  = []
            for i in range(self.k):
                vm  +=  [ self.decode_vec(self.v,
                            vbs[ i*self.v_sz : (i+1)*self.v_sz]) ]
                rr  =   self.decode_vec( self.k * self.o,
                            vbs[ self.k * self.v_sz : ] )

            #   M = v^T*L
            mm = [ [ bytearray(self.o) for _ in range(self.m) ]
                                        for _ in range(self.k) ]
            for r in range(self.k):
                for j in range(self.o):
                    t = [0,0,0,0]
                    for c in range(self.v):
                        self.bs_mul_add(t, lm[c][j], vm[r][c])
                    tcol = self.bs_nibbles(t, self.m)
                    for i in range(self.m):
                        mm[r][i][j] = tcol[i]

            #   v_i^t * P^(1) * v_j
            vpvm =  [ [ [0,0,0,0] for _ in range(self.k) ]
                                    for _ in range(self.k) ]
            for r in range(self.v):
                for j in range(self.k):
                    t   = [0,0,0,0]
                    for c in range(r, self.v):
                        self.bs_mul_add( t, p1m[r][c], vm[j][c] )
                    #   fold as upper triangular
                    for c in range(j):
                        self.bs_mul_add( vpvm[c][j], t, vm[c][r] )
                    for c in range(j, self.k):
                        self.bs_mul_add( vpvm[j][c], t, vm[c][r] )

            yd  =   self.m + (self.k * (self.k + 1) // 2)
            ad  =   self.k * self.o + 1
            y   =   mt + bytearray(yd - self.m)
            am  =   [ bytearray(ad) for _ in range(yd) ]

            l   = 0
            for i in range(self.k):
                for j in range(self.k - 1, i - 1, -1):

                    #   unbitslice the vPV and subtract from to y (t), shifted
                    #   by l positions
                    tmp = self.bs_nibbles(vpvm[i][j], self.m)
                    for c in range(self.m):
                        y[l + c] ^= tmp[c]

                    #   add M_i and M_j to A, shifted by l positions
                    for r in range(self.m):
                        for c in range(self.o):
                            am[r + l][i * self.o + c] ^= mm[j][r][c]
                            if i != j:
                                am[r + l][j * self.o + c] ^= mm[i][r][c]
                    l += 1

            #   reduce y and A (columns) mod f(x)
            for i in range(yd - self.m):
                for j in range(len(self.tail_f)):
                    y[i + j] ^= self.f_mul(y[i + self.m], self.tail_f[j])
                #y[i + m] = 0
            y = y[:self.m]

            for i in range(yd - self.m):
                for j in range(len(self.tail_f)):
                    t = self.tail_f[j]
                    for c in range(ad):
                        am[i + j][c] ^= self.f_mul(am[i + self.m][c], t)
            am = am[:self.m]

            x = self.sample_solution(am, y, rr)
            if x != None:
                break

        #   Finish and output the signature
        s   = []
        for i in range(self.k):
            for r in range(self.v):
                t = vm[i][r]
                for j in range(self.o):
                    t ^= self.f_mul(om[r][j], x[i * self.o + j])
                s += [t]
            s += x[i*self.o : (i+1)*self.o]

        #   dbg_vec(s, 's')
        sig = self.encode_vec(s) + salt
        return sig

    def sign(self, msg, sk):
        sig = self.signature(sk, msg)
        return sig + msg        #   concatenate into a signed message

    #   === Verify

    def pk_map(self, s, epk):
        """ public map. """

        #   split open
        p1v = self.bs_split4_vec( epk[0 : self.p1_sz], self.m )
        p2v = self.bs_split4_vec( epk[self.p1_sz : self.p1_sz + self.p2_sz],
                                    self.m )
        p3v = self.bs_split4_vec( epk[self.p1_sz + self.p2_sz :
                                    self.p1_sz + self.p2_sz + self.p3_sz],
                                        self.m )

        #   unpack the triangular matrix p
        p1i = 0
        p2i = 0
        p3i = 0
        pm  =   [ [ [0,0,0,0] for _ in range(self.n) ]
                                for _ in range(self.n) ]
        for r in range(self.v):
            for c in range(r, self.v):
                pm[r][c] = p1v[p1i]
                p1i += 1
            for c in range(self.v, self.n):
                pm[r][c] = p2v[p2i]
                p2i += 1
        for r in range(self.v, self.n):
            for c in range(r, self.n):
                pm[r][c] = p3v[p3i]
                p3i += 1

        #   precalc shifts
        ls  = [ [0] * self.k for _ in range(self.k) ]
        l   = 0
        for r in range(self.k):
            for c in range(self.k - 1, r - 1, -1):
                ls[r][c] = l
                ls[c][r] = l
                l += 1

        #   S * P * S = S * (P * S)
        sps     =   [ [ [0,0,0,0] for _ in range(self.k) ]
                                    for _ in range(self.k) ]

        z = [0,0,0,0]
        for r in range(self.n):
            for c in range(self.k):
                #   P * S^t
                t = [0,0,0,0]
                for j in range(r, self.n):
                    self.bs_mul_add( t, pm[r][j], s[c][j] )
                #   S * P * S = S * (P * S)
                for i in range(self.k):
                    self.bs_mul_add( z, self.bs_shift4(t, ls[c][i]), s[i][r] )

        y = self.bs_nibbles( z, self.m + (self.k * (self.k+1) // 2) )

        #   reduce mod f(x)
        for i in range(l):
            for j in range(len(self.tail_f)):
                y[i + j] ^= self.f_mul(y[i + self.m], self.tail_f[j])

        return bytearray( y[0 : self.m] )


    def verify(self, pk, msg, sig):
        """ MAYO.Verify(pk, M, sig) """

        #   Expand
        epk = self.aes128ctr(pk[0:self.seed_pk_sz], self.p1_sz + self.p2_sz)
        epk += pk[self.seed_pk_sz : self.seed_pk_sz + self.p3_sz]

        #   Decode sig
        salt    = sig[self.sig_sz - self.salt_sz : self.sig_sz]
        s       = self.decode_vec(self.k * self.n, sig)
        sm      = []
        for i in range(self.k):
            sm += [ s[ i*self.n : (i+1)*self.n ] ]

        #   Hash message and derive t
        m_hash  = self.shake256(msg, self.hash_sz)
        t       = self.decode_vec( self.m,
                        self.shake256(m_hash + salt, (self.m + 1) // 2) )

        #   Compute P∗(s)
        y   =   self.pk_map(sm, epk)

        return  t == y

    def open(self, sm, pk):
        """ Verify a signed message  sm = sig + msg. Return msg or None. """
        sig     =   sm[:self.sig_sz]
        msg     =   sm[self.sig_sz:]
        if not self.verify(pk, msg, sig):
            return None
        return msg

#   === Mayo parameter sets

mayo_1  =   Mayo(   n=66, m=64, o=8, k=9, salt_sz=24, digest_sz=32,
                    tail_f=[8, 0, 2, 8, 0], alg_id='MAYO_1' )

mayo_2  =   Mayo(   n=78, m=64, o=18, k=4, salt_sz=24, digest_sz=32,
                    tail_f=[8, 0, 2, 8, 0], alg_id='MAYO_2' )

mayo_3  =   Mayo(   n=99, m=96, o=10, k=11, salt_sz=32, digest_sz=48,
                    tail_f=[2, 2, 0, 2, 0], alg_id='MAYO_3' )

mayo_5  =   Mayo(   n=133, m=128, o=12, k=12, salt_sz=40, digest_sz=64,
                    tail_f=[4, 8, 0, 4, 2], alg_id='MAYO_5' )

mayo_all    =   [   mayo_1, mayo_2, mayo_3, mayo_5  ]

