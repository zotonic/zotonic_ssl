%% @author Marc Worrell <marc@worrell.nl>
%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2012-2020 Marc Worrell, Maas-Maarten Zeeman
%% @doc SSL support functions, create self-signed certificates

%% Copyright 2012-2020 Marc Worrell, Maas-Maarten Zeeman
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

-module(zotonic_ssl_certs).
-author('Marc Worrell <marc@worrell.nl>').
-author('Maas-Maarten Zeeman <mmzeeman@xs4all.nl>').

-export([
    ensure_self_signed/3,
    generate_self_signed/3,
    ciphers/0,
    decode_cert/1,
    normalize_hostname/1
]).

-include_lib("public_key/include/public_key.hrl").

-define(BITS, "4096").

-type options() :: #{
        hostname => string() | binary(),
        servername => string() | binary()
    }.
-export_type([options/0]).


%% @doc Check if all certificates are available in the site's ssl directory
-spec ensure_self_signed( file:filename_all(), file:filename_all(), options() ) ->  ok | {error, term()}.
ensure_self_signed(CertFile, PemFile, Options) ->
    case {filelib:is_file(CertFile), filelib:is_file(PemFile)} of
        {true, true} ->
            case check_keyfile(PemFile) of
                ok -> ok;
                {error, _} = E -> E
            end;
        {_, _} ->
            generate_self_signed(CertFile, PemFile, Options)
    end.

check_keyfile(Filename) ->
    case file:read_file(Filename) of
        {ok, <<"-----BEGIN PRIVATE KEY", _/binary>>} ->
            {error, {need_rsa_private_key, Filename, "use: openssl rsa -in sitename.key -out sitename.pem"}};
        {ok, Bin} ->
            case public_key:pem_decode(Bin) of
                [] -> {error, {no_private_keys_found, Filename}};
                _ -> ok
            end;
        {error, _} = Error ->
            {error, {cannot_read_pemfile, Filename, Error}}
    end.

-spec generate_self_signed( file:filename_all(), file:filename_all(), options() ) -> ok | {error, term()}.
generate_self_signed(CertFile, PemFile, Options) ->
    % lager:info("Generating self-signed ssl keys in '~s'", [PemFile]),
    case z_filelib:ensure_dir(PemFile) of
        ok ->
            % _ = file:change_mode(filename:dirname(PemFile), 8#00700),
            KeyFile = filename:rootname(PemFile) ++ ".key",
            Command = "openssl req -x509 -nodes"
                    ++ " -days 3650"
                    ++ " -sha256"
                    ++ " -subj '/CN=" ++ hostname(Options)
                             ++"/O=" ++ servername(Options)
                             ++"'"
                    ++ " -newkey rsa:"++?BITS++" "
                    ++ " -keyout " ++ z_filelib:os_filename(KeyFile)
                    ++ " -out " ++ z_filelib:os_filename(CertFile),
            % error_logger:info_msg("SSL: ~p", [Command]),
            Result = os:cmd(Command),
            % error_logger:info_msg("SSL: ~p", [Result]),
            case file:read_file(KeyFile) of
                {ok, <<"-----BEGIN PRIVATE KEY", _/binary>>} ->
                    os:cmd("openssl rsa -in "++KeyFile++" -out "++PemFile),
                    _ = file:change_mode(KeyFile, 8#00600),
                    _ = file:change_mode(PemFile, 8#00600),
                    _ = file:change_mode(CertFile, 8#00644),
                    error_logger:info_msg("SSL: Generated SSL self-signed certificate in '~s'", [KeyFile]),
                    ok;
                {ok, <<"-----BEGIN RSA PRIVATE KEY", _/binary>>} ->
                    file:rename(KeyFile, PemFile),
                    _ = file:change_mode(PemFile, 8#00600),
                    _ = file:change_mode(CertFile, 8#00644),
                    error_logger:info_msg("SSL: Generated SSL self-signed certificate in '~s'", [KeyFile]),
                    ok;
                _Error ->
                    error_logger:error_msg("SSL: Failed generating self-signed ssl keys in '~s' (output was ~s)",
                                           [PemFile, Result]),
                    {error, openssl}
            end;
        {error, _} = Error ->
            {error, {ensure_dir, Error, PemFile}}
    end.

hostname(#{ hostname := Hostname }) ->
    normalize_hostname(Hostname);
hostname(_Options) ->
    {ok, Hostname} = inet:gethostname(),
    normalize_hostname(Hostname).

servername(#{ servername := Servername }) ->
    normalize_servername(Servername);
servername(_Options) ->
    {ok, Hostname} = inet:gethostname(),
    normalize_servername(Hostname).


normalize_servername(Hostname) when is_binary(Hostname) ->
    normalize_hostname( binary_to_list(Hostname) );
normalize_servername(Servername) when is_list(Servername) ->
    [ C || C <- Servername, is_valid_hostname_char(C) ].

normalize_hostname(Hostname) when is_binary(Hostname) ->
    normalize_hostname( binary_to_list(Hostname) );
normalize_hostname(Hostname) when is_list(Hostname) ->
    [ to_lower(C) || C <- Hostname, is_valid_hostname_char(C) ].

to_lower(C) when C >= $A, C =< $Z -> C + 32;
to_lower(C) -> C.

is_valid_hostname_char($.) -> true;
is_valid_hostname_char(C) when C >= $a, C =< $z -> true;
is_valid_hostname_char(C) when C >= $A, C =< $Z -> true;
is_valid_hostname_char(C) when C >= $0, C =< $9 -> true;
is_valid_hostname_char($-) -> true;
is_valid_hostname_char(_) -> false.



%% @todo reorder cipher list? See: https://sparanoid.com/note/http2-and-ecdsa-cipher-suites/
%% ECDHE-RSA-AES128-GCM-SHA256 and ECDHE-ECDSA-AES128-GCM-SHA256 should be at the top.
%% Otherwise Chrome will give ERR_SPDY_INADEQUATE_TRANSPORT_SECURITY
%% There is a problem with Firefox, which *needs* a cipher suite not implemented by Erlang
%% https://github.com/tatsuhiro-t/lucid/blob/ce8654a75108c15cc786424b3faf1a8e945bfd53/README.rst#current-status
ciphers() ->
     [
        "ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-SHA384","ECDHE-RSA-AES256-SHA384", "ECDHE-ECDSA-DES-CBC3-SHA",
        "ECDH-ECDSA-AES256-GCM-SHA384","ECDH-RSA-AES256-GCM-SHA384","ECDH-ECDSA-AES256-SHA384",
        "ECDH-RSA-AES256-SHA384","DHE-DSS-AES256-GCM-SHA384","DHE-DSS-AES256-SHA256",
        "AES256-GCM-SHA384","AES256-SHA256","ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES128-SHA256","ECDHE-RSA-AES128-SHA256",
        "ECDH-ECDSA-AES128-GCM-SHA256","ECDH-RSA-AES128-GCM-SHA256","ECDH-ECDSA-AES128-SHA256",
        "ECDH-RSA-AES128-SHA256","DHE-DSS-AES128-GCM-SHA256","DHE-DSS-AES128-SHA256",
        "AES128-GCM-SHA256","AES128-SHA256","ECDHE-ECDSA-AES256-SHA",
        "ECDHE-RSA-AES256-SHA","DHE-DSS-AES256-SHA","ECDH-ECDSA-AES256-SHA",
        "ECDH-RSA-AES256-SHA","AES256-SHA","ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA","DHE-DSS-AES128-SHA","ECDH-ECDSA-AES128-SHA",
        "ECDH-RSA-AES128-SHA","AES128-SHA"
    ].
    % ssl:cipher_suites().


%% @doc Decode a certificate file, return common_name, not_after etc.
-spec decode_cert(file:filename_all()) -> {ok, map()} | {error, not_a_certificate}.
decode_cert(CertFile) ->
    {ok, CertData} = file:read_file(CertFile),
    PemEntries = public_key:pem_decode(CertData),
    case public_key:pem_entry_decode(hd(PemEntries)) of
        {'Certificate', #'TBSCertificate'{} = TBS, _, _} ->
            #'Validity'{notAfter = NotAfter} = TBS#'TBSCertificate'.validity,
            Subject = decode_subject(TBS#'TBSCertificate'.subject),
            SANs = decode_sans(TBS#'TBSCertificate'.extensions),
            {ok, #{
                not_after => decode_time(NotAfter),
                common_name => maps:get(cn, Subject, undefined),
                subject_alt_names => SANs
            }};
        _ ->
            {error, not_a_certificate}
    end.

decode_time({utcTime, [Y1,Y2,_M1,_M2,_D1,_D2,_H1,_H2,_M3,_M4,_S1,_S2,$Z] = T}) ->
    case list_to_integer([Y1,Y2]) of
        N when N >= 50 ->
            decode_time({generalTime, [$1,$9|T]});
        _ ->
            decode_time({generalTime, [$2,$0|T]})
    end;
decode_time({_,[Y1,Y2,Y3,Y4,M1,M2,D1,D2,H1,H2,M3,M4,S1,S2,$Z]}) ->
    Year  = list_to_integer([Y1, Y2, Y3, Y4]),
    Month = list_to_integer([M1, M2]),
    Day   = list_to_integer([D1, D2]),
    Hour  = list_to_integer([H1, H2]),
    Min   = list_to_integer([M3, M4]),
    Sec   = list_to_integer([S1, S2]),
    {{Year, Month, Day}, {Hour, Min, Sec}}.

decode_subject({rdnSequence, _} = R) ->
    {rdnSequence, List} = pubkey_cert_records:transform(R, decode),
    lists:foldl(
            fun
                (#'AttributeTypeAndValue'{type=?'id-at-commonName', value=CN}, Acc) ->
                    Acc#{ cn => decode_value(CN) };
                (_, Acc) ->
                    Acc
            end,
            #{},
            lists:flatten(List)).

decode_sans([]) ->
    [];
decode_sans([#'Extension'{extnID=?'id-ce-subjectAltName', extnValue=V} | _]) ->
    case 'OTP-PUB-KEY':decode('SubjectAltName', iolist_to_binary(V)) of
        {ok, Vs} -> lists:map(fun decode_value/1, Vs);
        _ -> []
    end;
decode_sans([_|Exts]) ->
    decode_sans(Exts).

decode_value({dNSName, Name}) -> iolist_to_binary(Name);
decode_value({printableString, P}) -> iolist_to_binary(P);
decode_value({utf8String, B}) -> B.

