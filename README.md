#   mayo-py

2024-10-21  Markku-Juhani O. Saarinen  mjos@iki.fi

Python implementation of the [MAYO signature scheme](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/MAYO-spec-web.pdf) which is a candidate in the first round of the [NIST PQC Signature On-Ramp](https://csrc.nist.gov/Projects/pqc-dig-sig/round-1-additional-signatures)

This implementation supports all four parameter sets in the specification, and also the public and secret key compression methods. Here are the basic parameters and the public key, secret key, and signature sizes in bytes.

| Param  |   n |   m |  o |  k |   PK | SK | Sig |
|--------|-----|-----|----|----|------|----|-----|
| MAYO_1 |  66 |  64 |  8 |  9 | 1168 | 24 | 321 |
| MAYO_2 |  78 |  64 | 18 |  4 | 5488 | 24 | 180 |
| MAYO_3 |  99 |  96 | 10 | 11 | 2656 | 32 | 577 |
| MAYO_5 | 133 | 128 | 12 | 12 | 5008 | 40 | 838 |

	
##  Implementation Notes

The implementation is self-contained in file ([mayo.py](mauo.py)). You will need Python3 with AES and SHAKE crypto primitives; try `pip3 install pycryptodome` if those are not installed.

##  Running Known Answer Tests

The known answer testbench ([kat_test.py](kat_test.py)) can be executed via `python3 kat_test.py` and checked against the provided KAT checksums.

The [kat](kat) directory contains various test vectors extracted from the NIST submission package. The `*.rsp.1` files just contain the first entry of each response file. Due to the large size of keys in the KAT files, sha256 hashes are provided for 1, 10, and 100 entries in files [kat1.txt](kat/kat1.txt), [kat10.txt](kat/kat10.txt), and [kat100.txt](kat/kat100.txt), respectively.

The KAT tester computes sha256 hashes of KAT output in the same format as the NIST .rsp file. By default we compute first 10 vectors, but you may modify the `katnum` variable in [kat_test.py](kat_test.py) to produce hashes of more vectors.

**Example:** Print the hashes of first 10 test vectors(default):

```
$ python3 kat_test.py 
# 10/10 MAYO_1
40965966a084bba4e6be63c355800052d761d27b71238e7d2e8ee3f888019056 MAYO_1 (10)
# 10/10 MAYO_2
4f1958017f0d3f3449c5cfe47f362de584b5a0a2e519bcde58646ee82e97865c MAYO_2 (10)
# 10/10 MAYO_3
850146603532ecb4d62ef757579f94f705ca70c8db8e01163219d42e3a3ed109 MAYO_3 (10)
# 10/10 MAYO_5
83492419e687113a5cd66c03edc2b9f180a58424501f2ea7da805123f9d8f4cf MAYO_5 (10)
```

We can observe that these are the same as those stored:
```
$ cat kat/kat10.txt 
40965966a084bba4e6be63c355800052d761d27b71238e7d2e8ee3f888019056  PQCsignKAT_24_MAYO_1.rsp.10
4f1958017f0d3f3449c5cfe47f362de584b5a0a2e519bcde58646ee82e97865c  PQCsignKAT_24_MAYO_2.rsp.10
850146603532ecb4d62ef757579f94f705ca70c8db8e01163219d42e3a3ed109  PQCsignKAT_32_MAYO_3.rsp.10
83492419e687113a5cd66c03edc2b9f180a58424501f2ea7da805123f9d8f4cf  PQCsignKAT_40_MAYO_5.rsp.10
```

