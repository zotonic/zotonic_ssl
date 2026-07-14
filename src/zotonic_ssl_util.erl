%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2026 Marc Worrell, Maas-Maarten Zeeman
%% @doc SSL support functions, create self-signed certificates

%% Copyright 2026 Marc Worrell
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(zotonic_ssl_util).

-export([ os_filename/1 ]).

%% @doc Simple escape function for filenames as commandline arguments.
%% The result includes quotes.
-spec os_filename( string()|binary() ) -> string().
os_filename(A) when is_binary(A) ->
    os_filename(binary_to_list(A));
os_filename(A) when is_list(A) ->
    {Family, _} = os:type(),
    os_filename(Family, filename:nativename(lists:flatten(A))).

-spec os_filename(unix | win32, string()) -> string().
os_filename(unix, A) ->
    [$' | os_filename_unix(lists:flatten(A), [])];
os_filename(win32, A) ->
    [$" | os_filename_win32(lists:flatten(A), [])].

os_filename_unix([], Acc) ->
    lists:reverse([$'|Acc]);
os_filename_unix([$'|Rest], Acc) ->
    os_filename_unix(Rest, lists:reverse("'\\''", Acc));
os_filename_unix([C|Rest], Acc) ->
    os_filename_unix(Rest, [C|Acc]).

os_filename_win32([], Acc) ->
    lists:reverse([$"|Acc]);
os_filename_win32([$\\|Rest], Acc) ->
    os_filename_win32_bs(Rest, 1, Acc);
os_filename_win32([$"|Rest], Acc) ->
    os_filename_win32(Rest, [$",$\\|Acc]);
os_filename_win32([C|Rest], Acc) ->
    os_filename_win32(Rest, [C|Acc]).

os_filename_win32_bs([], N, Acc) ->
    os_filename_win32([], lists:duplicate(N * 2, $\\) ++ Acc);
os_filename_win32_bs([$\\|Rest], N, Acc) ->
    os_filename_win32_bs(Rest, N + 1, Acc);
os_filename_win32_bs([$"|Rest], N, Acc) ->
    os_filename_win32(Rest, [$" | lists:duplicate(N * 2 + 1, $\\) ++ Acc]);
os_filename_win32_bs([C|Rest], N, Acc) ->
    os_filename_win32(Rest, [C | lists:duplicate(N, $\\) ++ Acc]).
