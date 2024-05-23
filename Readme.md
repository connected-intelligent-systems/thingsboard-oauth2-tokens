# thingsboard-oauth2-tokens

This service acts as a bridge for secure authentication, allowing users and systems to convert OAuth 2.0 tokens into valid tokens for ThingsBoard. This process ensures that access to ThingsBoard services and resources is governed by modern security standards, leveraging OAuth 2.0's robust authorization framework. By integrating with this service, clients can seamlessly authenticate against ThingsBoard, ensuring a secure and efficient user experience while accessing device data and management functionalities.

## How to run this image

```shell
docker run -it --rm --name thingsboard-ouath2-tokens \
-e POSTGRES_URL='postgresql://postgres:5432/thingsboard' \
-e TOKEN_SIGNING_KEY='secretsigningkey' \
-e OAUTH2_CERTS_ENDPOINT='http://keycloak-headless:8080/realms/dataspace/protocol/openid-connect/certs' \
-e THINGSBOARD_AUTH_URL='http://thingsboard-node:8080/api/auth/login' \
registry.fsn.iotx.materna.work/registry/public/thingsboard-oauth2-tokens:latest
```

## Authors

Sebastian Alberternst <sebastian.alberternst@dfki.de>

## License

MIT 
