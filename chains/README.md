# Original public eMudhra test chains

Source: <https://emudhra.we-have-a-problem.com/chains.zip>

Downloaded 2026-10-22. The source archive describes these as chains captured
on 2026-10-20, with the leaf certificate first and the remaining certificates
as untrusted intermediates. These files contain public certificates only.

SHA-256 of the downloaded source archive:

```text
8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95
```

The 12 chains cover DV, EV, and OV TLS intermediates, generations G3B and G3C,
with both eMudhra and AAA parent paths. The fleet script compresses and embeds
these fixtures in the remote payload. It never fetches replacement certificates
through the target host's network, so a TLS interception proxy cannot substitute
the certificates being checked.

Following the source archive's verification instructions:

```bash
openssl verify -no-CApath -CAfile /etc/pki/tls/certs/ca-bundle.crt \
  -untrusted FILE.pem FILE.pem
```

Successful verification means that bundle still trusts the original chain.
Missing or untrusted issuers demonstrate the required rejection. Other errors,
such as expiry or unsupported algorithms, are inconclusive for distrust.
