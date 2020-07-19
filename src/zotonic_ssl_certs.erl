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
    check_keyfile/1,
    decode_cert/1,
    normalize_hostname/1,

    ciphers/0,
    safe_protocol_versions/0,
    filter_unavailable_cipher_suites/1,
    filter_unsafe_cipher_suites/1,
    sort_cipher_suites/1,
    suite_sort_criteria/1
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

%% @doc Check if the file contains a valid private key.
-spec check_keyfile( file:filename_all() ) -> ok | {error, Reason}
    when Reason :: {no_private_keys_found, file:filename_all()}
                 | {cannot_read_pemfile, file:filename_all(), file:posix()}.
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

%% @doc Generate a self signed certificate with the hostname and servername in the options. The hostname
%% and servername both default to inet:gethostname/0. The key is generated in the PemFile and the
%% certificate in the CertFile. If the directory of the PemFile does not exist then it is created.
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
                    ++ " -subj \"/CN=" ++ hostname(Options)
                             ++"/O=" ++ servername(Options)
                             ++"\""
                    ++ " -newkey rsa:"++?BITS++" "
                    ++ " -keyout \"" ++ string:strip(z_filelib:os_filename(KeyFile), both, $') ++ "\""
                    ++ " -out \"" ++ string:strip(z_filelib:os_filename(CertFile), both, $') ++ "\"",
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
%% This is a re-ordered list that comes from
%% https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#23-use-secure-cipher-suites
-spec ciphers() -> list( string() ).
ciphers() ->
    ["ECDHE-ECDSA-AES256-GCM-SHA384",
     "ECDHE-ECDSA-AES128-GCM-SHA256",
     "ECDHE-RSA-AES256-GCM-SHA384",
     "ECDHE-RSA-AES128-GCM-SHA256",

     "ECDHE-ECDSA-AES256-SHA384",
     "ECDHE-ECDSA-AES256-SHA",
     "ECDHE-ECDSA-AES128-SHA256",
     "ECDHE-ECDSA-AES128-SHA",

     "ECDHE-RSA-AES256-SHA384",
     "ECDHE-RSA-AES256-SHA",
     "ECDHE-RSA-AES128-SHA256",
     "ECDHE-RSA-AES128-SHA",

     "DHE-RSA-AES256-GCM-SHA384",
     "DHE-RSA-AES128-GCM-SHA256",

     "DHE-RSA-AES256-SHA256",
     "DHE-RSA-AES256-SHA",
     "DHE-RSA-AES128-SHA256",
     "DHE-RSA-AES128-SHA"].

%% @doc Return a list with safe tls versions provided by this erlang installation.
-spec safe_protocol_versions() -> [ssl:tls_version()].
safe_protocol_versions() ->
    {available, Versions} = proplists:lookup(available, ssl:versions()),
    [V || V <- Versions, is_safe_version(V)].


%% @doc Remove cipher suites which are not available by the underlying crypto library.
filter_unavailable_cipher_suites(Suites) ->
    [S || S <- Suites, is_available_cipher_suite(S)].

%% @doc Remove the unsafe cipher suites from the provided list.
filter_unsafe_cipher_suites(Suites) ->
    [S || S <- Suites, is_safe_cipher_suite(S)].

%% @doc Sort the cipher suite into a preferrable safe order.
sort_cipher_suites(Suites) ->
    lists:reverse(lists:sort(
                    fun(SuiteA, SuiteB) ->
                            suite_sort_criteria(SuiteA) =< suite_sort_criteria(SuiteB)
                    end,
                    Suites)).


%% @doc Decode a certificate file, return map with 'common_name', 'subject_alt_names' and 'not_after'.
-spec decode_cert(file:filename_all()) -> {ok, map()} | {error, not_a_certificate}.
decode_cert(CertFile) ->
    decode_cert_data(file:read_file(CertFile)).

decode_cert_data({ok, CertData}) ->
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

decode_sans(asn1_NOVALUE) ->
    [];
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

%% Return true if the tls protocol is a known safe protocol.
is_safe_version(sslv3) -> false;
is_safe_version(tlsv1) -> false;
is_safe_version('tlsv1.1') -> false;
is_safe_version('tlsv1.2') -> true;
is_safe_version('tlsv1.3') -> true;
is_safe_version(_) -> false.

%% Return true if the cipher suite is safe.
is_safe_cipher_suite({KeyExchange, Cipher, Mac}) ->
    is_safe_cipher_suite(KeyExchange, Cipher, Mac);
is_safe_cipher_suite({KeyExchange, Cipher, Mac, _Prf}) ->
    is_safe_cipher_suite(KeyExchange, Cipher, Mac);
is_safe_cipher_suite(#{key_exchange := KeyExchange, cipher := Cipher, mac := Mac}) ->
    is_safe_cipher_suite(KeyExchange, Cipher, Mac);
is_safe_cipher_suite(Str) when is_list(Str) orelse is_binary(Str) ->
    is_safe_cipher_suite(str_to_suite(Str)).

is_safe_cipher_suite(KeyExchange, Cipher, Mac) ->
    is_safe_key_exchange(KeyExchange) andalso is_safe_cipher(Cipher) andalso is_safe_mac(Mac).
    
%% Return true if the key exchange algorithm is safe.
is_safe_key_exchange(rsa) -> false;
is_safe_key_exchange(ecdh_rsa) -> false;
is_safe_key_exchange(ecdh_ecdsa) -> false;
is_safe_key_exchange(_) -> true.

%% Return true if the cipher is safe
is_safe_cipher(null) -> false;
is_safe_cipher(des_cbc) -> false;
is_safe_cipher(rc4_128) -> false;
is_safe_cipher('3des_ede_cbc') -> false;
is_safe_cipher(aes_128_ccm) -> false;
is_safe_cipher(aes_128_ccm_8) -> false;
is_safe_cipher(_) -> true.

%% Return true if the mac is safe
is_safe_mac(md5) -> false;
is_safe_mac(_) -> true.


%% Return the suite sort criteria, a tuple with things we want to rank the suites with.
suite_sort_criteria({KeyExchange, Cipher, Mac}) ->
    suite_sort_criteria(KeyExchange, Cipher, Mac);
suite_sort_criteria({KeyExchange, Cipher, Mac, _Prf}) ->
    suite_sort_criteria(KeyExchange, Cipher, Mac);
suite_sort_criteria(#{key_exchange := KeyExchange, cipher := Cipher, mac := Mac}) ->
    suite_sort_criteria(KeyExchange, Cipher, Mac);
suite_sort_criteria(Str) when is_list(Str) orelse is_binary(Str) ->
    suite_sort_criteria(str_to_suite(Str)).

suite_sort_criteria(KeyExchange, Cipher, Mac) ->
    {has_ec_key_exchange(KeyExchange),
     has_aead(Cipher),
     has_ecdsa(KeyExchange),
     effective_key_bits(Cipher),
     hash_size(Mac)}.

%% Return suite information based on the binary, or list provided. Needs a lot of workarounds
%% for various erlang releases.
str_to_suite(Str) ->
    true = ensure_loaded(ssl),
    GotStrToSuite = erlang:function_exported(ssl, str_to_suite, 1),
    GotSSLCipherFormat = ensure_loaded(ssl_cipher_format),

    if GotStrToSuite -> 
           %% OTP-22 and up
           ssl:str_to_suite(Str);
       GotSSLCipherFormat ->
           %% OTP-21
           str_to_suite(ssl_cipher_format, Str);
       true ->
           %% Older Erlang releases
           str_to_suite(ssl_cipher, Str)
    end.

%%
str_to_suite(Mod, Str) when is_list(Str) ->
    str_to_suite(Mod, Mod:openssl_suite(Str));
str_to_suite(Mod, Str) when is_binary(Str) ->
    Mod:suite_definition(Str).


%% Return true if the cipher suite is available in the cryptolib of this erlang
%% installation
is_available_cipher_suite(Str) when is_list(Str) ->
    is_available_cipher_suite(str_to_suite(Str));
is_available_cipher_suite(Suite) ->
    ensure_loaded(ssl),
    
    HasSSLFilterCipherSuites = erlang:function_exported(ssl, filter_cipher_suites, 2),

    Suites = if HasSSLFilterCipherSuites ->
                    %% OPT-20.3 and up
                    ssl:filter_cipher_suites([Suite], []);
                true ->
                    throw(no_ssl_filter_cipher_suites)
             end,

    length(Suites) == 1.

    
has_ec_key_exchange(ecdhe_rsa) -> true;
has_ec_key_exchange(ecdhe_ecdsa) -> true;
has_ec_key_exchange(_) -> false.

has_aead(aes_128_gcm) -> true;
has_aead(aes_256_gcm) -> true;
has_aead(chacha20_poly1305) -> true;
has_aead(_) -> false.

has_ecdsa(ecdhe_ecdsa) -> true;
has_ecdsa(ecdh_ecdsa) -> true;
has_ecdsa(_) -> false.

effective_key_bits(des_cbc) -> 56;
effective_key_bits(rc4_128) -> 128;
effective_key_bits(aes_128_ccm) -> 128;
effective_key_bits(aes_128_ccm_8) -> 128;
effective_key_bits(aes_128_cbc) -> 128;
effective_key_bits(aes_128_gcm) -> 128;
effective_key_bits('3des_ede_cbc') -> 168;
effective_key_bits('aes_256_cbc') -> 256;
effective_key_bits('aes_256_gcm') -> 256;
effective_key_bits(aes_256_ccm) -> 256;
effective_key_bits(aes_256_ccm_8) -> 256;
effective_key_bits(chacha20_poly1305) -> 256;
effective_key_bits(_) -> 0.

hash_size(md5) -> 16;
hash_size(sha) -> 20;
hash_size(sha256) -> 32;
hash_size(sha384) -> 48;
hash_size(sha512) -> 64;
hash_size(_) -> 0.

% Tries to load a module when it is not loaded, returns false when it was not possible
% to ensure that the module was loaded.
ensure_loaded(Module) ->
    %% Ensure the module is loaded. Needed in order to check for exported functions.
    case code:ensure_loaded(Module) of
        {module, Module} -> true;
        {error, _} -> false
    end.

