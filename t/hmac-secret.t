use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        function get_testcert(name)
            local f = io.open("/lua-resty-jwt/testcerts/" .. name)
            local contents = f:read("*all")
            f:close()
            return contents
        end

        -- HS256 token MACed with the given secret, built without jwt:sign
        function hs256_token(secret)
            local jwt = require "resty.jwt"
            local hmac = require "resty.hmac"
            local msg = jwt:jwt_encode('{"typ":"JWT","alg":"HS256"}') .. "."
                .. jwt:jwt_encode('{"foo":"bar"}')
            local sig = hmac:new(secret, hmac.ALGOS.SHA256):final(msg)
            return msg .. "." .. jwt:jwt_encode(sig)
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: HS256 token MACed with an RSA public key PEM is not verified with that PEM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pem = get_testcert("pubkey.pem")
            local jwt_obj = jwt:verify(pem, hs256_token(pem))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
invalid secret for HS256: PEM key material cannot be used as an HMAC secret
--- no_error_log
[error]


=== TEST 2: HS256 token MACed with a certificate PEM is not verified with that PEM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pem = get_testcert("cert.pem")
            local jwt_obj = jwt:verify(pem, hs256_token(pem))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
invalid secret for HS256: PEM key material cannot be used as an HMAC secret
--- no_error_log
[error]


=== TEST 3: HS256 token MACed with a DER public key is not verified with that key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            local der = pkey.new(get_testcert("pubkey.pem")):tostring("public", "DER")
            local jwt_obj = jwt:verify(der, hs256_token(der))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
invalid secret for HS256: DER key material cannot be used as an HMAC secret
--- no_error_log
[error]


=== TEST 4: empty secret is not verified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify("", hs256_token(""))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
invalid secret for HS256: empty secret
--- no_error_log
[error]


=== TEST 5: HS256 and HS512 refuse to sign with empty, PEM or DER secrets
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            local pem = get_testcert("cert-key.pem")
            local der = pkey.new(pem):tostring("private", "DER")
            for _, alg in ipairs({"HS256", "HS512"}) do
                for _, secret in ipairs({"", pem, der}) do
                    local ok, err = pcall(jwt.sign, jwt, secret,
                        {header={typ="JWT", alg=alg}, payload={foo="bar"}})
                    ngx.say(ok, " ", err.reason)
                end
            end
        }
    }
--- request
GET /t
--- response_body
false invalid secret for HS256: empty secret
false invalid secret for HS256: PEM key material cannot be used as an HMAC secret
false invalid secret for HS256: DER key material cannot be used as an HMAC secret
false invalid secret for HS512: empty secret
false invalid secret for HS512: PEM key material cannot be used as an HMAC secret
false invalid secret for HS512: DER key material cannot be used as an HMAC secret
--- no_error_log
[error]


=== TEST 6: plain HS256 and HS512 secrets still sign and verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- the second secret is shaped like a DER SEQUENCE but holds no key
            for _, secret in ipairs({"lua-resty-jwt", "0\2ab"}) do
                for _, alg in ipairs({"HS256", "HS512"}) do
                    local token = jwt:sign(secret,
                        {header={typ="JWT", alg=alg}, payload={foo="bar"}})
                    local jwt_obj = jwt:verify(secret, token)
                    ngx.say(alg, " ", jwt_obj.verified, " ", jwt_obj.payload.foo)
                end
            end
        }
    }
--- request
GET /t
--- response_body
HS256 true bar
HS512 true bar
HS256 true bar
HS512 true bar
--- no_error_log
[error]


=== TEST 7: RS256 still verifies with a public key PEM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = jwt:sign(get_testcert("cert-key.pem"),
                {header={typ="JWT", alg="RS256"}, payload={foo="bar"}})
            local jwt_obj = jwt:verify(get_testcert("cert-pubkey.pem"), token)
            ngx.say(jwt_obj.verified, " ", jwt_obj.payload.foo)
        }
    }
--- request
GET /t
--- response_body
true bar
--- no_error_log
[error]
