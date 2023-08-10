# Rego:OIDC

This app validates a jwttoken sent to the `/auth`-endpoint by:
* signature based on a the OIDC `/certs`-endpoint 
* `/.well-known/openid-configuration`-endpoint
* `.exp` in jwt-token