%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @copyright 2020 Maas-Maarten Zeeman
%% @doc SSL support functions, easily get safe options to initialize safe ssl sockets

%% Copyright 2020 Maas-Maarten Zeeman
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

-module(zotonic_ssl_option).
-author('Maas-Maarten Zeeman <mmzeeman@xs4all.nl>').

-export([
    ciphers/0,
    safe_protocol_versions/0,
    remove_unavailable_cipher_suites/1,
    remove_unsafe_cipher_suites/1,
    sort_cipher_suites/1,
    suite_sort_criteria/1
]).

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
remove_unavailable_cipher_suites(Suites) ->
    [S || S <- Suites, is_available_cipher_suite(S)].

%% @doc Remove the unsafe cipher suites from the provided list.
remove_unsafe_cipher_suites(Suites) ->
    [S || S <- Suites, is_safe_cipher_suite(S)].

%% @doc Sort the cipher suite into a preferrable safe order.
sort_cipher_suites(Suites) ->
    lists:reverse(lists:sort(
                    fun(SuiteA, SuiteB) ->
                            suite_sort_criteria(SuiteA) =< suite_sort_criteria(SuiteB)
                    end,
                    Suites)).

%%
%% Helpers
%%

%% Return true if the tls protocol is a known safe protocol.
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
is_safe_key_exchange(ecdhe_ecdsa) -> true;
is_safe_key_exchange(ecdhe_rsa) -> true;
is_safe_key_exchange(dhe_rsa) -> true;
is_safe_key_exchange(dhe_dss) -> true;
is_safe_key_exchange(_) -> false.

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
                    ssl_cipher:filter_suites([Suite])
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


