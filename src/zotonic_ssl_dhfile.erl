%% @author Marc Worrell <marc@worrell.nl>
%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2020 Marc Worrell, Maas-Maarten Zeeman
%% @doc SSL support functions, ensure the DH file.

%% Copyright 2020 Marc Worrell, Maas-Maarten Zeeman
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

-module(zotonic_ssl_dhfile).
-author('Marc Worrell <marc@worrell.nl>').
-author('Maas-Maarten Zeeman <mmzeeman@xs4all.nl>').

-export([
    is_dhfile/1,
    ensure_dhfile/1,
    ensure_dhfile/2,
    write_dhfile/1,
    write_dhfile/2
]).

-type dhgroup() :: ffdhe2048 | ffdhe3072 | ffdhe4096.

-export_type([dhgroup/0]).

-define(DEFAULT_DHGROUP, ffdhe3072).

%% @doc Check if the file is a DH file.
-spec is_dhfile( file:filenam_all() ) -> boolean().
is_dhfile(Filename) ->
    case file:read_file(Filename) of
        {ok, <<"-----BEGIN DH PARAMETERS", _/binary>>} -> true;
        _ -> false
    end.

%% @doc Check if the DH file does exist, if not then create the DH file.
%% Missing directories are created. The DH group used will be 'ffdhe3072'.
-spec ensure_dhfile( file:filename_all() ) -> ok | {error, term()}.
ensure_dhfile(Filename) ->
    ensure_dhfile(Filename, ?DEFAULT_DHGROUP).

%% @doc Check if the DH file does exist, if not then create the DH file.
%% Missing directories are created.
-spec ensure_dhfile( file:filename_all(), dhgroup() ) -> ok | {error, term()}.
ensure_dhfile(Filename, Group) ->
    case filelib:is_file(Filename) of
        true ->
            ok;
        false ->
            case z_filelib:ensure_dir(Filename) of
                ok ->
                    write_dhfile(Filename, Group);
                {error, _} = Error ->
                    Error
            end
    end.

%% @doc Write a DH file, directory must exist. DH group will be 'ffdhe3072'.
-spec write_dhfile( file:filename_all() ) -> ok | {error, term()}.
write_dhfile(Filename) ->
    write_dhfile(Filename, ?DEFAULT_DHGROUP).

%% @doc Write a DH file. Overwrites any existing file. 
%% The file mode will be set to rw for the user.
-spec write_dhfile( file:filename_all(), dhgroup() ) -> ok | {error, term()}.
write_dhfile(Filename, Group) ->
    case file:write_file(Filename, dh_params(Group)) of
        ok ->
            _ = file:change_mode(Filename, 8#00600),
            ok;
        {error, _Reason} = Error ->
            Error
    end.

%%
%% Recommended pre-configured DH groups per IETF (RFC 7919:
%% https://tools.ietf.org/html/rfc7919).
%%
%% These values were obtained from
%% https://wiki.mozilla.org/Security/Server_Side_TLS#ffdhe2048
%%

dh_params(ffdhe2048) ->
    <<"-----BEGIN DH PARAMETERS-----\n",
      "MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n",
      "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n",
      "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n",
      "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n",
      "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n",
      "ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==\n",
      "-----END DH PARAMETERS-----">>;
dh_params(ffdhe3072) ->
    <<"-----BEGIN DH PARAMETERS-----\n",
      "MIIBiAKCAYEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n",
      "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n",
      "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n",
      "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n",
      "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n",
      "ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3\n",
      "7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32\n",
      "nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZsYu\n",
      "N///////////AgEC\n",
      "-----END DH PARAMETERS-----">>;
dh_params(ffdhe4096) ->
    <<"-----BEGIN DH PARAMETERS-----\n",
    "MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n",
    "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n",
    "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n",
    "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n",
    "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n",
    "ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3\n",
    "7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32\n",
    "nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e\n",
    "8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx\n",
    "iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K\n",
    "zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=\n",
    "-----END DH PARAMETERS-----">>.
