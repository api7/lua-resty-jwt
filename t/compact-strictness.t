use Test::Nginx::Socket::Lua;



repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: JWS needs exactly 3 non-empty parts
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = jwt:sign("secret", {
                header = { typ = "JWT", alg = "HS256" },
                payload = { foo = "bar" },
            })
            local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
            local none = jwt:jwt_encode('{"alg":"none"}')
            local cases = {
                { "valid", token },
                { "empty header", "." .. p .. "." .. s },
                { "empty payload", h .. ".." .. s },
                { "empty signature", h .. "." .. p .. "." },
                { "alg none", none .. "." .. p .. "." },
                { "two parts", h .. "." .. p },
                { "trailing dot", token .. "." },
                { "leading dot", "." .. token },
                { "doubled first dot", h .. ".." .. p .. "." .. s },
                { "doubled second dot", h .. "." .. p .. ".." .. s },
                { "quadrupled dot", h .. "." .. p .. "...." .. s },
                { "all dots doubled", h .. ".." .. p .. ".." .. s },
                { "all dots", "...." },
                { "empty", "" },
                { "six parts", token .. "..." },
            }
            for _, c in ipairs(cases) do
                local obj = jwt:verify("secret", c[2])
                ngx.say(c[1], ": ", obj.verified, " ", obj.reason)
            end
            local obj = jwt:load_jwt(nil)
            ngx.say("nil: ", obj.valid, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
valid: true everything is awesome~ :p
empty header: false invalid jwt string: empty header
empty payload: false invalid jwt string: empty payload
empty signature: false invalid jwt string: empty signature
alg none: false invalid jwt string: empty signature
two parts: false invalid jwt string
trailing dot: false invalid jwt string
leading dot: false invalid jwt string
doubled first dot: false invalid jwt string
doubled second dot: false invalid jwt string
quadrupled dot: false invalid jwt string
all dots doubled: false invalid algorithm: HS256
all dots: false invalid jwt string: empty header
empty: false invalid jwt string
six parts: false invalid jwt string
nil: false invalid jwt string
--- no_error_log
[error]



=== TEST 2: JWS parts must be canonical base64url
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            local secret = "lua-resty-jwt-compact-strictness"
            -- kid "??>>" makes the encoded header contain '-' and '_'
            local token = jwt:sign(secret, {
                header = { typ = "JWT", alg = "HS256", kid = "??>>" },
                payload = { foo = "bar" },
            })
            local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")

            -- same signature bytes with the unused low bits of the last
            -- character set (32 bytes -> 43 chars, 2 unused bits)
            local idx = alphabet:find(s:sub(-1), 1, true) - 1
            local alt_sig = s:sub(1, -2) .. alphabet:sub(idx + 2, idx + 2)

            local cases = {
                { "canonical", token },
                { "sig trailing bits", h .. "." .. p .. "." .. alt_sig },
                { "sig padded", h .. "." .. p .. "." .. s .. "=" },
                { "sig over-padded", h .. "." .. p .. "." .. s .. "==" },
                { "sig whitespace", h .. "." .. p .. "." .. s .. " " },
                { "header std alphabet", h:gsub("%-", "+"):gsub("_", "/") .. "." .. p .. "." .. s },
                { "payload padded", h .. "." .. p .. "=." .. s },
            }
            for _, c in ipairs(cases) do
                local obj = jwt:verify(secret, c[2])
                ngx.say(c[1], ": ", tostring(obj.verified), " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
canonical: true everything is awesome~ :p
sig trailing bits: false invalid jwt string: non-canonical base64url in signature
sig padded: true everything is awesome~ :p
sig over-padded: false invalid jwt string: non-canonical base64url in signature
sig whitespace: false invalid jwt string: non-canonical base64url in signature
header std alphabet: false invalid jwt string: non-canonical base64url in header
payload padded: false invalid jwt string: non-canonical base64url in payload
--- no_error_log
[error]



=== TEST 3: dir JWE needs 5 parts and an empty encrypted key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local token = jwt:sign(key, {
                header = { alg = "dir", enc = "A256GCM" },
                payload = { foo = "bar" },
            })
            local p = {}
            for part in (token .. "."):gmatch("([^.]*)%.") do p[#p + 1] = part end
            local function say(label, str)
                local obj = jwt:verify(key, str)
                ngx.say(label, ": ", obj.verified, " ", obj.reason)
            end

            say("dir", token)
            say("dir with key", table.concat({ p[1], "AAAA", p[3], p[4], p[5] }, "."))
            say("dir 4 parts", table.concat({ p[1], p[3], p[4], p[5] }, "."))
            say("dir trailing dot", token .. ".")
            say("dir leading dot", "." .. token)
            say("dir doubled dot", table.concat({ p[1], p[2], p[3], p[4] }, ".") .. ".." .. p[5])
            local names = { "header", "encrypted key", "iv", "ciphertext", "tag" }
            for _, i in ipairs({ 1, 3, 5 }) do
                local q = { p[1], p[2], p[3], p[4], p[5] }
                q[i] = ""
                say(names[i], table.concat(q, "."))
            end
        }
    }
--- request
GET /t
--- response_body
dir: true everything is awesome~ :p
dir with key: false JWE encrypted key must be empty for dir
dir 4 parts: false invalid jwt string
dir trailing dot: false invalid jwt string
dir leading dot: false invalid jwt string
dir doubled dot: false invalid jwt string
header: false invalid jwt string: empty header
iv: false invalid jwt string: empty initialization vector
tag: false invalid jwt string: empty authentication tag
--- no_error_log
[error]



=== TEST 4: JWE parts must be canonical base64url
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            local key = string.rep("k", 32)
            local token = jwt:sign(key, {
                header = { alg = "dir", enc = "A256GCM" },
                payload = { foo = "bar" },
            })
            local p = {}
            for part in (token .. "."):gmatch("([^.]*)%.") do p[#p + 1] = part end

            -- 16-byte tag -> 22 chars, the last char carries 4 unused bits
            local tag = p[5]
            local idx = alphabet:find(tag:sub(-1), 1, true) - 1
            local alt = { p[1], p[2], p[3], p[4], tag:sub(1, -2) .. alphabet:sub(idx + 2, idx + 2) }

            local ok = jwt:verify(key, token)
            local bad = jwt:verify(key, table.concat(alt, "."))
            local padded = jwt:verify(key, table.concat({ p[1], p[2], p[3] .. "==", p[4], p[5] }, "."))
            ngx.say("canonical: ", tostring(ok.verified))
            ngx.say("tag trailing bits: ", tostring(bad.verified), " ", bad.reason)
            ngx.say("iv padded: ", tostring(padded.verified), " ", padded.reason)
            local tag_padded = jwt:verify(key, table.concat({ p[1], p[2], p[3], p[4], p[5] .. "==" }, "."))
            ngx.say("tag padded: ", tostring(tag_padded.verified))
        }
    }
--- request
GET /t
--- response_body
canonical: true
tag trailing bits: false invalid jwt string: non-canonical base64url in authentication tag
iv padded: false invalid jwt string: non-canonical base64url in initialization vector
tag padded: true
--- no_error_log
[error]



=== TEST 5: AES-GCM JWE with an empty plaintext keeps its empty ciphertext
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local j = jwt.new()
            j:set_payload_encoder(function() return "" end)
            j:set_payload_decoder(function(s) return { plaintext = s } end)
            local token = j:sign(key, {
                header = { alg = "dir", enc = "A256GCM" },
                payload = {},
            })
            local p = {}
            for part in (token .. "."):gmatch("([^.]*)%.") do p[#p + 1] = part end
            ngx.say("parts: ", #p, " ciphertext empty: ", tostring(p[4] == ""))
            local obj = j:verify(key, token)
            ngx.say("verified: ", tostring(obj.verified), " [", obj.payload and obj.payload.plaintext, "]")
        }
    }
--- request
GET /t
--- response_body
parts: 5 ciphertext empty: true
verified: true []
--- no_error_log
[error]



=== TEST 6: JWS signed over padded parts, as AWS ALB issues them
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local hmac = require "resty.hmac"
            local function b64url_padded(s)
                return (ngx.encode_base64(s):gsub("%+", "-"):gsub("/", "_"))
            end
            local secret = "lua-resty-jwt-compact-strictness"
            local h = b64url_padded('{"typ":"JWT","alg":"HS256","kid":"a"}')
            local p = b64url_padded('{"foo":"bar"}')
            local input = h .. "." .. p
            local s = b64url_padded(hmac:new(secret, hmac.ALGOS.SHA256):final(input))
            ngx.say("padded: ", h:sub(-1) == "=", " ", p:sub(-1) == "=", " ", s:sub(-1) == "=")
            local obj = jwt:verify(secret, input .. "." .. s)
            ngx.say(tostring(obj.verified), " ", obj.reason, " ", obj.payload and obj.payload.foo)
        }
    }
--- request
GET /t
--- response_body
padded: true true true
true everything is awesome~ :p bar
--- no_error_log
[error]
