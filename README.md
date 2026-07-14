# Zotonic SSL

Useful SSL routines for Erlang/Elixir projects.

## Certificates

### Generate self-signed certificates

Example:

```erlang
PemFile = "/my/secure/path/cert.pem",
CertFile = "/my/secure/path/cert.crt",
Options = #{
        hostname => "localhost.example.com",
        servername => "MyServerName"
    },
ok = zotonic_ssl_certs:ensure_self_signed(CertFile, PemFile, Options).
```

The hostname and the servername default to the hostname returned by `inet:gethostname/0`.
By default a 4096 bit RSA key is generated.

To generate an ECDSA key using the default P-256 curve:

```erlang
Options = #{
        hostname => "localhost.example.com",
        servername => "MyServerName",
        key_type => ecdsa
    },
ok = zotonic_ssl_certs:generate_self_signed(CertFile, PemFile, Options).
```

Set `elliptic_curve => secp384r1` to use P-384 instead. The supported elliptic
curves are `secp256r1` (the default) and `secp384r1`.


### Ensure self-signed certificates

Similar to generating, except that this routine does nothing if the files already exist.

```
ok = zotonic_ssl_certs:ensure_self_signed(CertFile, PemFile, Options).
```

Existing certificate and key files are not replaced, even when the requested
`key_type` differs from the existing key.

### Decode a certificate

Extract some information from a certificate.

```erlang
{ok, Map} = decode_cert("path/to/cert.crt").
```

Keys returned:

 * `not_after` Erlang DateTime with the expiration date (Validity)
 * `common_name` The CN (aka the hostname) for the certificate
 * `subject_alt_names` A list of alternative names the certificate is valid for (SANs)


## Write a DH file

The `zotonic_ssl_dhfile` routines handle the creation of DH (aka DHE) files.
You can select from a couple of predefined DH files.

### Generate a DH file

```erlang
ok = zotonic_ssl_dhfile:ensure_dhfile("path/to/myfile.dh").
```

This ensures that the path is created and that the DH file is written.
It defaults to the `ffdhe3072` DH group.

The following DH groups are possible: `ffdhe2048`, `ffdhe3072`, `ffdhe4096`

To generate with a specific DH group:

```erlang
ok = zotonic_ssl_dhfile:ensure_dhfile("path/to/myfile.dh", ffdhe2048).
```

Or, if no check on the existance of a valid DH file is needed:

```erlang
ok = zotonic_ssl_dhfile:write_dhfile("path/to/myfile.dh").
```

or

```erlang
ok = zotonic_ssl_dhfile:write_dhfile("path/to/myfile.dh", ffdhe2048).
```


## License

The Apache License v2.
