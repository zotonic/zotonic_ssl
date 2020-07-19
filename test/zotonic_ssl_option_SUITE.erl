-module(zotonic_ssl_option_SUITE).

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
        safe_protocol_versions,
        sort_cipher_suite,
        ciphers_are_safe,
        release_provides_safe_ciphers
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

safe_protocol_versions(_Config) ->
    Versions = zotonic_ssl_option:safe_protocol_versions(),

    % Check if there are safe protocols available. This test
    true = (length(Versions) > 0),
    true = (length(Versions) =< 2),
    ok.

sort_cipher_suite(_Config) ->
    Ciphers = zotonic_ssl_option:ciphers(),
    Sorted = zotonic_ssl_option:sort_cipher_suites(Ciphers),

    % Check if we provide the ciphers sorted.
    true = (length(Ciphers) == length(Sorted)),
    true = (Ciphers == Sorted),

    ok.

ciphers_are_safe(_Config) ->
    Ciphers = zotonic_ssl_option:ciphers(),
    Filtered = zotonic_ssl_option:remove_unsafe_cipher_suites(Ciphers),

    % The default ciphers we provide should be safe. 
    true = (length(Ciphers) == length(Filtered)),

    true = (Ciphers == Filtered),

    ok.

release_provides_safe_ciphers(_Config) ->
    % Check if this erlang release provides safe ciphers.
    Available = zotonic_ssl_option:remove_unavailable_cipher_suites(zotonic_ssl_option:ciphers()),
    true = (length(Available) > 0),
    ok.

