use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: Verify A256CBC-HS512 Direct Encryption with a Shared Symmetric Key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234" ..
                               "12341234123412341234123412341234"

            local jwt_obj = jwt:verify(
              shared_key,
              "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0." ..
              ".M927Z_hNTmumFQE0rtRQCQ.nnd7AoE_2dgvws2-iay8qA.d" ..
              "kyZuuks4Qm9Cd7VfEVSs07pi_Kyt0INVHTTesUC2BM"
            )

            ngx.say(
                "alg: ", jwt_obj.header.alg, "\\n",
                "enc: ", jwt_obj.header.enc, "\\n",
                "payload: ", cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
alg: dir
enc: A256CBC-HS512
payload: {"foo":"bar"}
valid: true
verified: true
--- no_error_log
[error]



=== TEST 2: Verify A128CBC-HS256 Direct Encryption with a Shared Symmetric Key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"

            local jwt_obj = jwt:verify(
                shared_key,
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." ..
                ".U6emIwy_yVkagUwQ4EjdFA.FrapgQVvG3uictQz9NPPMw.n" ..
                "MoW0ShdgCN0JHw472SJjQ"
            )

            ngx.say(
                "alg: ", jwt_obj.header.alg, "\\n",
                "enc: ", jwt_obj.header.enc, "\\n",
                "payload: ", cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
alg: dir
enc: A128CBC-HS256
payload: {"foo":"bar"}
valid: true
verified: true
--- no_error_log
[error]



=== TEST 3: Dont fail if extra chars added
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"

            local jwt_obj = jwt:verify(
                shared_key,
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." ..
                ".U6emIwy_yVkagUwQ4EjdFA.FrapgQVvG3uictQz9NPPMw.n" ..
                "MoW0ShdgCN0JHw472SJjQ" ..
                "xxx"

            )
            ngx.say(
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
valid: true
verified: false
--- no_error_log
[error]



=== TEST 4: Encode A128CBC-HS256 Direct Encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"

            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = { foo = "bar" },
            }

            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)

            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]



=== TEST 5: Encode A256CBC-HS512 Direct Encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234" ..
                               "12341234123412341234123412341234"

            local table_of_jwt = {
              header = { alg = "dir", enc = "A256CBC-HS512" },
              payload = { foo = "bar" },
            }

            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)

            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]



=== TEST 6: Use rsa oeap 256 for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]



=== TEST 7: Use rsa oeap 256 for encryption invalid typ
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "INVALID",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
            }

            local success, err = pcall(function () jwt:sign(
                        get_testcert("cert-pubkey.pem"),
                        table_of_jwt
                )
            end)
            ngx.say(err.reason)
        ';
    }
--- request
GET /t
--- response_body
invalid typ: INVALID
--- no_error_log
[error]



=== TEST 8: Use rsa oeap 256 for encryption invalid key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
            }

            local success, err = pcall(function () jwt:sign(
                        "invalid RSA",
                        table_of_jwt
                    )
            end)
            ngx.say(err.reason)
        ';
    }
--- request
GET /t
--- response_body
Decode secret is not a valid cert/public key: 
--- no_error_log
[error]



=== TEST 9: Use rsa oeap 256 for encryption invalid enc algo
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local success, err = pcall(function () jwt:sign(
                        get_testcert("cert-pubkey.pem"),
                        table_of_jwt
                    )
            end)
            ngx.say(err.reason)
        ';
    }
--- request
GET /t
--- response_body
unsupported payload encryption algorithm :A256CBC
--- no_error_log
[error]



=== TEST 10: Use rsa oeap 256 for encryption with custom payload encoder/decoder
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt_module = require "resty.jwt"
            local cjson = require "cjson"

            local function split_string(str, delim)
                local result = {}
                local sep = string.format("([^%s]+)", delim)
                for m in str:gmatch(sep) do
                    result[#result+1]=m
                end
                return result
            end

            local jwt = jwt_module.new()

            jwt:set_payload_encoder(function(tab)
                                        local str = ""
                                        for i, v in ipairs(tab) do
                                            if (i ~= 1) then
                                                str = str .. ":"
                                            end
                                            str = str .. ":" .. v
                                         end
                                         return str
                                     end
                                    )

            jwt:set_payload_decoder(function(str)
                                         return split_string(str, ":")
                                     end
                                    )

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  "foo" , "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]

=== TEST 11: Use rsa oeap 256 with aes-256-gcm for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]

=== TEST 12: verify jwe create with rsa-oaep256 and aes-256-gcm with invalid tag
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = "eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoibXlLZXkiLCJhbGciOiJSU0EtT0FFUC0yNTYifQ" .. "." ..
                              "HcMWB6Gh03hYZjsrH08L69aDe8FKv6bZ8e-M8_FggGFyyRdmq1zbHchdbUKMxup1rW9HaIKlNgYpaHiWh7f_BRWAmH4oMzqop4_SmA1LN4nkz3d-P2_MBO2Rm9yVA-4Y4ju0F9QqQ7QbvPLiBknKOmKwEHzL371jN52OK5gByLEA8sSE75rIbfHVoTGtPkz_aIrDp40gcPyojMtMEy4Edm3og2yC8FZl80YRIlVeo9y5qfuwRG5IIFYv60vCdfPXzNN_OBGXUuHPr4szVAu3FV3bwXbM_EyuYPMc1crH42cXFz9zTei8eONU1xmA1H3Z2Jplgj0zUOJtLsgOSeZCwQ" .. "." ..
                              "mROZHYnNXD2Db6vl" .. "." ..
                              "iO8YLN0EiL3QfmP40Q" .. "." ..
                              "vlvUs6U8P6coJk1wyjwxFw"
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            local err = "false"
            if string.find(jwt_obj.reason, "failed to decrypt payload") then
                err = "true"
            end
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "verified: ", jwt_obj.verified, "\\n",
                "error: ", err
            )
        ';
    }
--- request
GET /t
--- response_body
false
verified: false
error: true
--- no_error_log
[error]
