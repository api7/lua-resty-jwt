use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        local jwt = require "resty.jwt"

        jwe_t = {}

        jwe_t.keys = {
            ["A128CBC-HS256"] = string.rep("a", 32),
            ["A256CBC-HS512"] = string.rep("b", 64),
            ["A256GCM"] = string.rep("c", 32),
        }

        function jwe_t.sign(enc)
            return jwt:sign(jwe_t.keys[enc], {
                header = { alg = "dir", enc = enc },
                payload = { foo = "bar" },
            })
        end

        function jwe_t.split(tok)
            local parts = {}
            for p in (tok .. "."):gmatch("([^.]*)%.") do
                parts[#parts + 1] = p
            end
            return parts
        end

        -- replace part i of the token with the encoding of raw
        function jwe_t.set_part(tok, i, raw)
            local parts = jwe_t.split(tok)
            parts[i] = jwt:jwt_encode(raw)
            return table.concat(parts, ".")
        end

        -- xor byte n of part i with x
        function jwe_t.flip(tok, i, n, x)
            local raw = jwt:jwt_decode(jwe_t.split(tok)[i])
            local b = string.char(bit.bxor(raw:byte(n), x))
            return jwe_t.set_part(tok, i, raw:sub(1, n - 1) .. b .. raw:sub(n + 1))
        end

        function jwe_t.part(tok, i)
            return jwt:jwt_decode(jwe_t.split(tok)[i])
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: valid JWE loads and verifies for every enc
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            for _, enc in ipairs({"A128CBC-HS256", "A256CBC-HS512", "A256GCM"}) do
                local tok = jwe_t.sign(enc)
                local obj = jwt:verify(jwe_t.keys[enc], tok)
                ngx.say(enc, ": ", obj.valid, " ", obj.verified, " ", obj.reason, " ",
                        cjson.encode(obj.payload), " ", #jwe_t.part(tok, 5))
            end
        }
    }
--- request
GET /t
--- response_body
A128CBC-HS256: true true everything is awesome~ :p {"foo":"bar"} 16
A256CBC-HS512: true true everything is awesome~ :p {"foo":"bar"} 32
A256GCM: true true everything is awesome~ :p {"foo":"bar"} 16
--- no_error_log
[error]



=== TEST 2: CBC-HS tampered ciphertext or tag gives the generic reason and runs no claim check
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local ran = 0
            local spec = { foo = function() ran = ran + 1 return true end }
            for _, enc in ipairs({"A128CBC-HS256", "A256CBC-HS512"}) do
                local tok = jwe_t.sign(enc)
                local cases = {
                    -- a changed ciphertext used to fail on padding, a changed tag on the MAC
                    ciphertext_last = jwe_t.flip(tok, 4, #jwe_t.part(tok, 4), 1),
                    ciphertext_first = jwe_t.flip(tok, 4, 1, 1),
                    tag = jwe_t.flip(tok, 5, 1, 1),
                }
                for _, name in ipairs({"ciphertext_last", "ciphertext_first", "tag"}) do
                    local loaded = jwt:load_jwt(cases[name], jwe_t.keys[enc])
                    local obj = jwt:verify(jwe_t.keys[enc], cases[name], spec)
                    ngx.say(enc, " ", name, ": ", loaded.valid, " ", loaded.reason, " ",
                            type(loaded.payload), " ", obj.verified, " ", obj.reason)
                end
            end
            ngx.say("claim checks: ", ran)
        }
    }
--- request
GET /t
--- response_body
A128CBC-HS256 ciphertext_last: false failed to decrypt JWE nil false failed to decrypt JWE
A128CBC-HS256 ciphertext_first: false failed to decrypt JWE nil false failed to decrypt JWE
A128CBC-HS256 tag: false failed to decrypt JWE nil false failed to decrypt JWE
A256CBC-HS512 ciphertext_last: false failed to decrypt JWE nil false failed to decrypt JWE
A256CBC-HS512 ciphertext_first: false failed to decrypt JWE nil false failed to decrypt JWE
A256CBC-HS512 tag: false failed to decrypt JWE nil false failed to decrypt JWE
claim checks: 0
--- no_error_log
[error]



=== TEST 3: CBC-HS changed IV is rejected before the payload is decrypted
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local seen = {}
            local spec = { foo = function(val) seen[#seen + 1] = val return true end }
            for _, enc in ipairs({"A128CBC-HS256", "A256CBC-HS512"}) do
                -- turns "bar" into "baz" in the single block of plaintext
                local tok = jwe_t.flip(jwe_t.sign(enc), 3, 11, bit.bxor(string.byte("r"), string.byte("z")))
                local loaded = jwt:load_jwt(tok, jwe_t.keys[enc])
                local obj = jwt:verify(jwe_t.keys[enc], tok, spec)
                ngx.say(enc, ": ", loaded.valid, " ", type(loaded.payload), " ", obj.verified, " ", obj.reason)
            end
            ngx.say("claim values seen: ", #seen)
        }
    }
--- request
GET /t
--- response_body
A128CBC-HS256: false nil false failed to decrypt JWE
A256CBC-HS512: false nil false failed to decrypt JWE
claim values seen: 0
--- no_error_log
[error]



=== TEST 4: CBC-HS tag of the wrong length is rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, enc in ipairs({"A128CBC-HS256", "A256CBC-HS512"}) do
                local tok = jwe_t.sign(enc)
                local tag = jwe_t.part(tok, 5)
                for _, n in ipairs({#tag - 1, 1}) do
                    local obj = jwt:load_jwt(jwe_t.set_part(tok, 5, tag:sub(1, n)), jwe_t.keys[enc])
                    ngx.say(enc, " ", n, ": ", obj.valid, " ", obj.reason)
                end
            end
        }
    }
--- request
GET /t
--- response_body
A128CBC-HS256 15: false invalid JWE authentication tag length
A128CBC-HS256 1: false invalid JWE authentication tag length
A256CBC-HS512 31: false invalid JWE authentication tag length
A256CBC-HS512 1: false invalid JWE authentication tag length
--- no_error_log
[error]



=== TEST 5: GCM truncated tags are rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = jwe_t.keys["A256GCM"]
            local tok = jwe_t.sign("A256GCM")
            local tag = jwe_t.part(tok, 5)
            for _, n in ipairs({15, 4, 1}) do
                local truncated = jwe_t.set_part(tok, 5, tag:sub(1, n))
                local loaded = jwt:load_jwt(truncated, key)
                local obj = jwt:verify(key, truncated)
                ngx.say(n, ": ", loaded.valid, " ", type(loaded.payload), " ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
15: false nil false invalid JWE authentication tag length
4: false nil false invalid JWE authentication tag length
1: false nil false invalid JWE authentication tag length
--- no_error_log
[error]



=== TEST 6: GCM changed ciphertext is rejected with any 1-byte tag
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = jwe_t.keys["A256GCM"]
            local tok = jwe_t.flip(jwe_t.sign("A256GCM"), 4, 11, bit.bxor(string.byte("r"), string.byte("z")))
            local accepted = 0
            for b = 0, 255 do
                local obj = jwt:verify(key, jwe_t.set_part(tok, 5, string.char(b)))
                if obj.verified or obj.payload then
                    accepted = accepted + 1
                end
            end
            ngx.say("accepted: ", accepted)
            ngx.say("full tag: ", jwt:verify(key, tok).reason)
        }
    }
--- request
GET /t
--- response_body
accepted: 0
full tag: failed to decrypt JWE
--- no_error_log
[error]



=== TEST 7: JWE without a key fails with a clean reason
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local rsa_header = jwt:jwt_encode(cjson.encode({alg = "RSA-OAEP-256", enc = "A256GCM"}))
            local tokens = {
                jwe_t.sign("A128CBC-HS256"),
                jwe_t.sign("A256GCM"),
                rsa_header .. ".AAAA.AAAA.AAAA.AAAA",
            }
            for _, tok in ipairs(tokens) do
                local a = jwt:load_jwt(tok)
                local b = jwt:load_jwt(tok, nil)
                ngx.say(a.valid, " ", a.reason, " | ", b.valid, " ", b.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false preshared key must not be null | false preshared key must not be null
false preshared key must not be null | false preshared key must not be null
false rsa private key must not be null | false rsa private key must not be null
--- no_error_log
[error]



=== TEST 8: JWE object that parse_jwe did not authenticate does not verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local obj = jwt:verify_jwt_obj(jwe_t.keys["A128CBC-HS256"], {
                typ = "JWE",
                valid = true,
                verified = false,
                header = { alg = "dir", enc = "A128CBC-HS256" },
                payload = { foo = "bar" },
                internal = {},
            })
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false JWE was not authenticated
--- no_error_log
[error]



=== TEST 9: claims of an authenticated JWE are still checked
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            for _, enc in ipairs({"A128CBC-HS256", "A256GCM"}) do
                local tok = jwe_t.sign(enc)
                local ok = jwt:verify(jwe_t.keys[enc], tok, { foo = validators.equals("bar") })
                local bad = jwt:verify(jwe_t.keys[enc], tok, { foo = validators.equals("baz") })
                ngx.say(enc, ": ", ok.verified, " ", ok.reason, " | ", bad.verified, " ", bad.reason)
            end
        }
    }
--- request
GET /t
--- response_body
A128CBC-HS256: true everything is awesome~ :p | false Claim 'foo' ('bar') returned failure
A256GCM: true everything is awesome~ :p | false Claim 'foo' ('bar') returned failure
--- no_error_log
[error]
