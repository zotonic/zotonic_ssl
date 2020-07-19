-module(zotonic_ssl_certs_SUITE).

-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").

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
        generate_self_signed,
        safe_protocol_versions,
        sort_cipher_suite,
        ciphers_are_safe,
        release_provides_safe_ciphers
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

generate_self_signed(Config) ->
    Dir = tmpdir(Config),
    CertFile = filename:join(Dir, "cert.crt"),
    PemFile = filename:join(Dir, "cert.pem"),
    Options = #{
        hostname => "Self-Signed.test",
        servername => "CommonTest"
    },
    ok = zotonic_ssl_certs:ensure_self_signed(CertFile, PemFile, Options),
    ok = zotonic_ssl_certs:check_keyfile(PemFile),
    {ok, CertInfo} = zotonic_ssl_certs:decode_cert(CertFile),
    #{
        common_name := <<"self-signed.test">>,
        not_after := {{_,_,_},{_,_,_}},
        subject_alt_names := []
    } = CertInfo,
    ok.

safe_protocol_versions(_Config) ->
    Versions = zotonic_ssl_certs:safe_protocol_versions(),

    % Check if there are safe protocols available. This test
    true = (length(Versions) > 0),
    true = (length(Versions) =< 2),
    ok.

sort_cipher_suite(_Config) ->
    Ciphers = zotonic_ssl_certs:ciphers(),
    Sorted = zotonic_ssl_certs:sort_cipher_suites(Ciphers),

    % Check if we provide the ciphers sorted.
    true = (length(Ciphers) == length(Sorted)),
    true = (Ciphers == Sorted),

    ok.

ciphers_are_safe(_Config) ->
    Ciphers = zotonic_ssl_certs:ciphers(),
    Filtered = zotonic_ssl_certs:remove_unsafe_cipher_suites(Ciphers),

    % The default ciphers we provide should be safe. 
    true = (length(Ciphers) == length(Filtered)),
    true = (Ciphers == Filtered),

    ok.

release_provides_safe_ciphers(_Config) ->
    % Check if this erlang release provides safe ciphers.
    Available = zotonic_ssl_certs:remove_unavailable_cipher_suites(zotonic_ssl_certs:ciphers()),
    true = (length(Available) > 0),
    ok.

tmpdir(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    filename:join([DataDir, "tmp"]).
