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

-export([ os_filename/1, ensure_dir/1 ]).

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



%% @doc Ensure the directory of a file is present. This will still work
%%      if a soft-link in the path refers to a missing directory.
-spec ensure_dir(file:filename_all()) -> ok | {error, term()}.
ensure_dir(Filename) ->
    case filelib:ensure_dir(Filename) of
        ok -> ok;
        {error, enoent} ->
            % Could be that there is a softlink to a missing directory in the path
            {LinkFile, Rest} = first_missing(filename:split(Filename), []),
            case file:read_link(LinkFile) of
                {ok, Link} ->
                    case make_link_target(Link, LinkFile, Rest) of
                        ok -> ensure_dir(Filename);
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.


make_link_target(Link, LinkFile, Rest) ->
    Target = case is_relative(Link) of
        true -> filename:join([ filename:dirname(LinkFile), Link ]);
        false -> Link
    end,
    case Rest of
        [] -> filelib:ensure_dir(filename:join([ Target ]));
        _ -> filelib:ensure_dir(filename:join([ Target, hd(Rest) ]))
    end.

is_relative(Path) ->
    case filename:split(Path) of
        [".."|_] -> true;
        ["."|_] -> true;
        [<<"..">>|_] -> true;
        [<<".">>|_] -> true;
        _ -> false
    end.


first_missing([], Acc) ->
    {filename:join(lists:reverse(Acc)), []};
first_missing([P|Ps], Acc) ->
    Acc1 = [P|Acc],
    Path = filename:join(lists:reverse(Acc1)),
    case filelib:is_file(Path) of
        true -> first_missing(Ps, [P|Acc]);
        false -> {Path, Ps}
    end.
