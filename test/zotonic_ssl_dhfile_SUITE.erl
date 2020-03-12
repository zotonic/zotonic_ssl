-module(zotonic_ssl_dhfile_SUITE).

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
        generate_dhfile
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

generate_dhfile(Config) ->
    File = dhfile(Config),
    ok = zotonic_ssl_dhfile:ensure_dhfile(File),
    true = zotonic_ssl_dhfile:is_dhfile(File),
    ok.


dhfile(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    filename:join([DataDir, "tmp", "dhfile.dh"]).
