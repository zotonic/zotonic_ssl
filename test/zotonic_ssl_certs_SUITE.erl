-module(zotonic_ssl_certs_SUITE).

-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%%--------------------------------------------------------------------
%% COMMON TEST CALLBACK FUNCTIONS
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

all() ->
    [
        decode_cert_with_sans,
        generate_self_signed,
        generate_self_signed_spaced_dir,
        generate_self_signed_ecdsa,
        generate_self_signed_ecdsa_secp384r1
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

decode_cert_with_sans(Config) ->
    CertFile = filename:join(?config(data_dir, Config), "sn.crt"),
    {ok, CertInfo} = zotonic_ssl_certs:decode_cert(CertFile),
    #{
        common_name := <<"sculpture-network.org">>,
        not_after := {{2026, 10, 12}, {8, 15, 25}},
        subject_alt_names := [
            <<"blakeward.com">>,
            <<"lists.sculpture-network.net">>,
            <<"lists.sculpture-network.org">>,
            <<"sculpture-network.net">>,
            <<"sculpture-network.org">>,
            <<"www.blakeward.com">>,
            <<"www.sculpture-network.net">>,
            <<"www.sculpture-network.org">>
        ]
    } = CertInfo,
    ok.

generate_self_signed(Config) ->
    Dir = tmpdir(Config),
    do_generate_self_signed(Dir).

generate_self_signed_spaced_dir(Config) ->
    Dir = spaced_dir(Config),
    do_generate_self_signed(Dir).

do_generate_self_signed(Dir) ->
    CertFile = filename:join(Dir, "cert.crt"),
    PemFile = filename:join(Dir, "cert.pem"),
    Options = #{
        hostname => "Self-Signed.test",
        servername => "CommonTest"
    },
    ok = zotonic_ssl_certs:ensure_self_signed(CertFile, PemFile, Options),
    ok = zotonic_ssl_certs:check_keyfile(PemFile),
    rsa = private_key_type(PemFile),
    {ok, CertInfo} = zotonic_ssl_certs:decode_cert(CertFile),
    #{
        common_name := <<"self-signed.test">>,
        not_after := {{_,_,_},{_,_,_}},
        subject_alt_names := []
    } = CertInfo,
    rsa = certificate_key_type(CertFile),
    ok.

generate_self_signed_ecdsa(Config) ->
    Dir = tmpdir(Config),
    CertFile = filename:join(Dir, "ecdsa-cert.crt"),
    PemFile = filename:join(Dir, "ecdsa-cert.pem"),
    Options = #{
        hostname => "ecdsa.test",
        servername => "CommonTest",
        key_type => ecdsa
    },
    ok = zotonic_ssl_certs:generate_self_signed(CertFile, PemFile, Options),
    {ecdsa, ?'secp256r1'} = private_key_type(PemFile),
    ecdsa = certificate_key_type(CertFile),
    ok.

generate_self_signed_ecdsa_secp384r1(Config) ->
    Dir = tmpdir(Config),
    CertFile = filename:join(Dir, "ecdsa-secp384r1-cert.crt"),
    PemFile = filename:join(Dir, "ecdsa-secp384r1-cert.pem"),
    Options = #{
        hostname => "ecdsa-384.test",
        servername => "CommonTest",
        key_type => ecdsa,
        elliptic_curve => secp384r1
    },
    ok = zotonic_ssl_certs:generate_self_signed(CertFile, PemFile, Options),
    {ecdsa, ?'secp384r1'} = private_key_type(PemFile),
    ecdsa = certificate_key_type(CertFile),
    ok.

private_key_type(PemFile) ->
    {ok, PemData} = file:read_file(PemFile),
    [PemEntry | _] = public_key:pem_decode(PemData),
    case public_key:pem_entry_decode(PemEntry) of
        #'RSAPrivateKey'{} ->
            rsa;
        #'ECPrivateKey'{parameters = {namedCurve, Curve}} ->
            {ecdsa, Curve}
    end.

certificate_key_type(CertFile) ->
    {ok, CertData} = file:read_file(CertFile),
    [{'Certificate', Der, _} | _] = public_key:pem_decode(CertData),
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
                algorithm = #'PublicKeyAlgorithm'{algorithm = Algorithm}
            }
        }
    } = public_key:pkix_decode_cert(Der, otp),
    case Algorithm of
        ?'rsaEncryption' -> rsa;
        ?'id-ecPublicKey' -> ecdsa
    end.


tmpdir(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    filename:join([DataDir, "tmp"]).

spaced_dir(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    filename:join([DataDir, "tmp", "A B"]).
