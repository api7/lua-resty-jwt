use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_worker_by_lua_block {
        local h = {}
        function h.cert(name)
            local f = assert(io.open("/lua-resty-jwt/testcerts/" .. name))
            local contents = f:read("*all")
            f:close()
            return contents
        end
        function h.b64url(s)
            return (ngx.encode_base64(s):gsub('+', '-'):gsub('/', '_'):gsub('=', ''))
        end
        -- signature bytes don't matter, the key type is checked first
        function h.token(alg, sig_len)
            return h.b64url('{"typ":"JWT","alg":"' .. alg .. '"}') ..
                "." .. h.b64url('{"sub":"test"}') ..
                "." .. h.b64url(string.rep("A", sig_len))
        end
        package.loaded["evp_hardening_helpers"] = h
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: ES256 token verified with an RSA public key fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            local jwt_obj = jwt:verify(h.cert("pubkey.pem"), h.token("ES256", 64))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
key is not an EC key
--- no_error_log
[error]


=== TEST 2: ES512 token verified with an RSA public key and certificate fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "pubkey.pem", "cert.pem" }) do
                local jwt_obj = jwt:verify(h.cert(name), h.token("ES512", 132))
                ngx.say(jwt_obj.verified, " ", jwt_obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false key is not an EC key
false key is not an EC key
--- no_error_log
[error]


=== TEST 3: RS256 token verified with an EC public key and certificate is rejected by key type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "ec_cert_p521_pubkey.pem", "ec_cert.pem" }) do
                local jwt_obj = jwt:verify(h.cert(name), h.token("RS256", 256))
                ngx.say(jwt_obj.verified, " ", jwt_obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false key is not an RSA key
false key is not an RSA key
--- no_error_log
[error]


=== TEST 4: ES256 signing with an RSA private key returns a signer error
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "privatekey.pem", "cert-key.pem" }) do
                local ok, err = pcall(jwt.sign, jwt, h.cert(name),
                    { header = { typ = "JWT", alg = "ES256" }, payload = { foo = "bar" } })
                ngx.say(ok, " ", type(err) == "table"
                    and err.reason:match("^signer error: ") ~= nil)
            end
        }
    }
--- request
GET /t
--- response_body
false true
false true
--- no_error_log
[error]


=== TEST 5: signers reject a missing private key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            ngx.say("RSASigner: ", evp.RSASigner:new(nil))
            ngx.say("ECSigner: ", evp.ECSigner:new(nil))
        }
    }
--- request
GET /t
--- response_body
RSASigner: nilMust pass a PEM private key
ECSigner: nilMust pass a PEM private key
--- no_error_log
[error]


=== TEST 6: ECSigner.get_raw_sig rejects malformed DER
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local signer = assert(evp.ECSigner:new(h.cert("ec_cert-key.pem")))
            local cases = {
                { "empty", "" },
                { "garbage", "not a DER signature" },
                { "truncated", "\48\6\2\1\1\2\1" },
                { "wrong tag", "\4\6\2\1\1\2\1\1" },
            }
            for _, c in ipairs(cases) do
                local raw, err = signer:get_raw_sig(c[2])
                ngx.say(c[1], ": ", raw, " ", err)
            end
        }
    }
--- request
GET /t
--- response_body
empty: nil Must pass a signature to convert
garbage: nil Invalid DER signature
truncated: nil Invalid DER signature
wrong tag: nil Invalid DER signature
--- no_error_log
[error]


=== TEST 7: ECSigner.get_raw_sig rejects r/s larger than the curve order and trailing data
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local signer = assert(evp.ECSigner:new(h.cert("ec_cert-key.pem")))
            -- SEQUENCE { INTEGER r (200 bytes), INTEGER 1 }
            local r = "\0" .. string.rep("\255", 199)
            local body = "\2\129\200" .. r .. "\2\1\1"
            local raw, err = signer:get_raw_sig("\48\129" .. string.char(#body) .. body)
            ngx.say("oversized r: ", raw, " ", err)

            local der = assert(signer:sign("hello", evp.CONST.SHA256_DIGEST))
            raw, err = signer:get_raw_sig(der .. "\0")
            ngx.say("trailing data: ", raw, " ", err)

            raw, err = signer:get_raw_sig(der)
            ngx.say("valid: ", #raw, " ", err)
            local verifier = assert(evp.ECVerifier:new(
                assert(evp.Cert:new(h.cert("ec_cert.pem")))))
            ngx.say("verifies: ", (verifier:verify("hello", raw, evp.CONST.SHA256_DIGEST)))
        }
    }
--- request
GET /t
--- response_body
oversized r: nil Invalid DER signature: r or s larger than curve order
trailing data: nil Invalid DER signature: trailing data
valid: 64 nil
verifies: true
--- no_error_log
[error]


=== TEST 8: ECSigner.get_raw_sig with an RSA key fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local ec_signer = assert(evp.ECSigner:new(h.cert("ec_cert-key.pem")))
            local der = assert(ec_signer:sign("hello", evp.CONST.SHA256_DIGEST))
            local rsa_signer = assert(evp.RSASigner:new(h.cert("privatekey.pem")))
            ngx.say(evp.ECSigner.get_raw_sig(rsa_signer, der))
        }
    }
--- request
GET /t
--- response_body
nilkey is not an EC key
--- no_error_log
[error]


=== TEST 9: verifiers and encryptor reject a key source without a public key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            ngx.say("RSAVerifier: ", evp.RSAVerifier:new({}))
            ngx.say("ECVerifier: ", evp.ECVerifier:new({}))
            ngx.say("RSAEncryptor: ", evp.RSAEncryptor:new({}))
        }
    }
--- request
GET /t
--- response_body
RSAVerifier: nilYou must pass in an key_source for a public key
ECVerifier: nilYou must pass in an key_source for a public key
RSAEncryptor: nilYou must pass in an key_source for a public key
--- no_error_log
[error]


=== TEST 10: RSAEncryptor with an EC public key is rejected by key type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local pub = assert(evp.PublicKey:new(h.cert("ec_cert_p521_pubkey.pem")))
            local enc = assert(evp.RSAEncryptor:new(pub))
            ngx.say(enc:encrypt("secret"))
        }
    }
--- request
GET /t
--- response_body
nilkey is not an RSA key
--- no_error_log
[error]


=== TEST 11: Cert.verify_trust with an unloadable trusted certs file fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local cert = assert(evp.Cert:new(h.cert("cert.pem")))
            local ok, err = cert:verify_trust("/nonexistent/trusted.pem")
            ngx.say("missing file: ", ok, " ", err:find("No such file or directory", 1, true) ~= nil)
            ok, err = cert:verify_trust("/lua-resty-jwt/testcerts")
            ngx.say("directory: ", ok, " ", type(err))
            ngx.say("nil: ", cert:verify_trust(nil))
            ngx.say("trusted: ", (cert:verify_trust("/lua-resty-jwt/testcerts/root.pem")))
        }
    }
--- request
GET /t
--- response_body
missing file: false true
directory: false string
nil: falseMust pass a trusted certs file path
trusted: true
--- no_error_log
[error]


=== TEST 12: x5c token with an unloadable trusted certs file returns a reason
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            local ssl = require "ngx.ssl"
            local der = assert(ssl.cert_pem_to_der(h.cert("cert.pem")))
            local token = jwt:sign(h.cert("cert-key.pem"), {
                header = { typ = "JWT", alg = "RS256", x5c = { ngx.encode_base64(der) } },
                payload = { foo = "bar" },
            })
            jwt:set_trusted_certs_file("/nonexistent/trusted.pem")
            local jwt_obj = jwt:verify(nil, token)
            jwt:set_trusted_certs_file(nil)
            ngx.say(jwt_obj.verified)
            local prefix = "Cert used to sign the JWT isn't trusted: "
            ngx.say(jwt_obj.reason:sub(1, #prefix) == prefix and #jwt_obj.reason > #prefix)
        }
    }
--- request
GET /t
--- response_body
false
true
--- no_error_log
[error]
