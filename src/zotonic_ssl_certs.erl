%% @author Marc Worrell <marc@worrell.nl>
%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2012-2026 Marc Worrell, Maas-Maarten Zeeman
%% @doc SSL support functions, create self-signed certificates

%% Copyright 2012-2026 Marc Worrell, Maas-Maarten Zeeman
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
    check_keyfile/1,
    decode_cert/1,
    normalize_hostname/1,
    ciphers/0
]).



-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/logger.hrl").

-define(RSA_BITS, "4096").
-define(DEFAULT_ELLIPTIC_CURVE, secp256r1).

-type key_type() :: rsa | ecdsa.
-type elliptic_curve() :: secp256r1 | secp384r1.

-type options() :: #{
        hostname => string() | binary(),
        servername => string() | binary(),
        key_type => key_type(),
        elliptic_curve => elliptic_curve()
    }.
-export_type([options/0, key_type/0, elliptic_curve/0]).

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

%% @doc Check if the file contains a valid private key.
-spec check_keyfile( file:filename_all() ) -> ok | {error, Reason}
    when Reason :: {no_private_keys_found, file:filename_all()}
                 | {cannot_read_pemfile, file:filename_all(), file:posix()}.
check_keyfile(Filename) ->
    case file:read_file(Filename) of
        {ok, Bin} ->
            case public_key:pem_decode(Bin) of
                [] -> {error, {no_private_keys_found, Filename}};
                _ -> ok
            end;
        {error, _} = Error ->
            {error, {cannot_read_pemfile, Filename, Error}}
    end.

%% @doc Generate a self signed certificate with the hostname and servername in the options. The hostname
%% and servername both default to inet:gethostname/0. The key type defaults to a 4096 bit RSA key. Set
%% `key_type' to `ecdsa' to generate an EC key; `elliptic_curve' defaults to `secp256r1'. The key is
%% generated in the PemFile and the certificate in the CertFile. If the directory of the PemFile does
%% not exist then it is created.
-spec generate_self_signed( file:filename_all(), file:filename_all(), options() ) -> ok | {error, term()}.
generate_self_signed(CertFile, PemFile, Options) ->
    case private_key_options(Options) of
        {ok, PrivateKeyOptions} ->
            generate_self_signed(CertFile, PemFile, Options, PrivateKeyOptions);
        {error, _} = Error ->
            Error
    end.

-spec generate_self_signed(file:filename_all(), file:filename_all(), options(), string()) ->
    ok | {error, term()}.
generate_self_signed(CertFile, PemFile, Options, PrivateKeyOptions) ->
    case zotonic_ssl_util:ensure_dir(PemFile) of
        ok ->
            KeyFile = filename:rootname(PemFile) ++ ".key",
            Command = "openssl req -x509 -nodes"
                    ++ " -days 3650"
                    ++ " -sha256"
                    ++ " -subj \"/CN=" ++ hostname(Options)
                             ++"/O=" ++ servername(Options)
                             ++"\""
                    ++ PrivateKeyOptions
                    ++ " -keyout " ++ zotonic_ssl_util:os_filename(KeyFile)
                    ++ " -out " ++ zotonic_ssl_util:os_filename(CertFile),
            execute_generate_self_signed(Command, CertFile, KeyFile, PemFile);
        {error, _} = Error ->
            {error, {ensure_dir, Error, PemFile}}
    end.

-spec execute_generate_self_signed(string(), file:filename_all(), file:filename_all(), file:filename_all()) ->
    ok | {error, openssl}.
execute_generate_self_signed(Command, CertFile, KeyFile, PemFile) ->
    Result = os:cmd(Command),
    ?LOG_DEBUG(#{
        text => <<"Generating self-signed key.">>,
        in => zotonic_ssl,
        what => cert_generate,
        openssl_command => unicode:characters_to_binary(Command, utf8),
        openssl_result => unicode:characters_to_binary(Result, utf8)
    }),
    case check_keyfile(KeyFile) of
        ok ->
            file:rename(KeyFile, PemFile),
            _ = file:change_mode(PemFile, 8#00600),
            _ = file:change_mode(CertFile, 8#00644),
            error_logger:info_msg("SSL: Generated SSL self-signed certificate in '~s'", [PemFile]),
            ok;
        {error, _} ->
            ?LOG_ERROR(#{
                text => <<"Error generating self-signed key.">>,
                result => error,
                reason => openssl,
                in => zotonic_ssl,
                what => cert_generate,
                openssl_command => unicode:characters_to_binary(Command, utf8),
                openssl_result => unicode:characters_to_binary(Result, utf8),
                pemfile => unicode:characters_to_binary(PemFile, utf8),
                keyfile => unicode:characters_to_binary(KeyFile, utf8)
            }),
            {error, openssl}
    end.

-spec private_key_options(map()) -> {ok, string()} | {error, term()}.
private_key_options(#{ key_type := ecdsa } = Options) ->
    Curve = maps:get(elliptic_curve, Options, ?DEFAULT_ELLIPTIC_CURVE),
    case openssl_curve_name(Curve) of
        {ok, CurveName} ->
            {ok, " -newkey ec -pkeyopt ec_paramgen_curve:" ++ CurveName};
        {error, _} = Error ->
            Error
    end;
private_key_options(#{ key_type := rsa }) ->
    {ok, " -newkey rsa:" ++ ?RSA_BITS};
private_key_options(#{ key_type := KeyType }) ->
    {error, {unsupported_key_type, KeyType}};
private_key_options(_Options) ->
    {ok, " -newkey rsa:" ++ ?RSA_BITS}.

-spec openssl_curve_name(term()) -> {ok, string()} | {error, term()}.
openssl_curve_name(secp256r1) ->
    {ok, "prime256v1"};
openssl_curve_name(secp384r1) ->
    {ok, "secp384r1"};
openssl_curve_name(Curve) ->
    {error, {unsupported_elliptic_curve, Curve}}.

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

%% @doc Normalize a hostname, filters invalid characters and lowercases the
%% all alphabetic characters.
-spec normalize_hostname( binary() | string() ) -> string().
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


%% @doc Return the list of ciphers for http connections.
-spec ciphers() -> list( string() ).
ciphers() ->
    zotonic_ssl_option:ciphers().

%% @doc Decode a certificate file, return map with 'common_name', 'subject_alt_names' and 'not_after'.
-spec decode_cert(file:filename_all()) -> {ok, map()} | {error, not_a_certificate}.
decode_cert(CertFile) ->
    decode_cert_data(file:read_file(CertFile)).

decode_cert_data({ok, CertData}) ->
    PemEntries = public_key:pem_decode(CertData),
    case hd(PemEntries) of
        {'Certificate', Der, _} ->
            #'OTPCertificate'{tbsCertificate = TBS} = public_key:pkix_decode_cert(Der, otp),
            #'Validity'{notAfter = NotAfter} = TBS#'OTPTBSCertificate'.validity,
            Subject = decode_subject(TBS#'OTPTBSCertificate'.subject),
            SANs = decode_sans(TBS#'OTPTBSCertificate'.extensions),
            {ok, #{
                not_after => decode_time(NotAfter),
                common_name => maps:get(cn, Subject, undefined),
                subject_alt_names => SANs
            }};
        _ ->
            {error, not_a_certificate}
    end;
decode_cert_data({error, _} = Error) ->
    Error.

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

decode_subject({rdnSequence, List}) ->
    lists:foldl(
            fun
                (#'AttributeTypeAndValue'{type=?'id-at-commonName', value=CN}, Acc) ->
                    Acc#{ cn => decode_value(CN) };
                (_, Acc) ->
                    Acc
            end,
            #{},
            lists:flatten(List)).

decode_sans(asn1_NOVALUE) ->
    [];
decode_sans([]) ->
    [];
decode_sans([#'Extension'{extnID=?'id-ce-subjectAltName', extnValue=SANs} | _]) ->
    lists:filtermap(
        fun
            ({dNSName, _} = SAN) -> {true, decode_value(SAN)};
            (_) -> false
        end,
        SANs);
decode_sans([_|Exts]) ->
    decode_sans(Exts).

decode_value({dNSName, Name}) -> iolist_to_binary(Name);
decode_value({printableString, P}) -> iolist_to_binary(P);
decode_value({utf8String, B}) -> B.
