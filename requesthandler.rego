package requesthandler
import future.keywords.if


default allow := false

jwkrepl := replace(data.JWKSURL, "\"", "")
oidcdiscoveryUrl := replace(data.OIDC_DISCOVERY, "\"", "")

token := trim_prefix(input.Header["Authorization"][0], "Bearer ")


issuers := {oidcdiscoveryUrl}

metadata_discovery(issuer) := http.send({
    "url": concat("", [issuers[issuer], "/.well-known/openid-configuration"]),
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 86400 # Cache response for 24 hours
}).body


jwks_request(url) := http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 360
})

jwks_url := concat("?", [
    jwkrepl,
    urlquery.encode_object({"kid": headers.kid}),
])

jwks := jwks_request(jwks_url).raw_body


jwt_verified := io.jwt.verify_rs256(token, jwks)

headers := io.jwt.decode(token)[0]
claims := io.jwt.decode(token)[1]
metadata := metadata_discovery(claims.iss)

issuer := claims.iss

now := time.now_ns()
jwtconvert := claims.exp*1000000000

valid := jwtconvert > now


token_presented := startswith(input.Header.Authorization[0], "Bearer ")


deny[msg] if {
    token_presented == false
    retval := {"verified": token_presented, "current_time": time.format(now), "token_presented": token_presented}
    msg := json.marshal(retval)
}

deny[msg] if {
    not jwt_verified
    retval := {"verified": jwt_verified, "current_time": time.format(now), "exp": time.format(jwtconvert), "details": {"jwks": json.unmarshal(jwks)}, "valid": valid}
    msg := json.marshal(retval)
}



deny[msg] if {
    valid == false
    retval := {"verified": jwt_verified, "current_time": time.format(now), "exp": time.format(jwtconvert), "details": {"jwks": json.unmarshal(jwks)}, "valid": valid}
    msg := json.marshal(retval)
}


allow[msg] if {
jwt_verified
valid == true
retval := {"verified": jwt_verified, "current_time": time.format(now), "exp": time.format(jwtconvert), "details" : {"claims": claims, "jwks": json.unmarshal(jwks)}, "valid": valid}
msg := json.marshal(retval)


}