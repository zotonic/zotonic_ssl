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
        generate_self_signed_spaced_dir
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

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
    {ok, CertInfo} = zotonic_ssl_certs:decode_cert(CertFile),
    #{
        common_name := <<"self-signed.test">>,
        not_after := {{_,_,_},{_,_,_}},
        subject_alt_names := []
    } = CertInfo,
    ok.


tmpdir(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    filename:join([DataDir, "tmp"]).

spaced_dir(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    filename:join([DataDir, "tmp", "A B"]).
