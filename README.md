# idcs-express-token-validator

Middleware for expressjs which validates access tokens provided by Oracle's IDCS.


## Installation

```bash
$ npm install idcs-express-token-validator
```

## Usage

The token validator exposes two methods, an initialisation method, initialise(), and a validator. The initialisation method takes a configuration object, which is used to connect to an IDCS instance and pull down the public keys required to validate supplied access tokens. Initialisation is performed asynchronously, and may take a few seconds to obtain the appropriate keys from the IDCS instance. During this time, all token validations will fail. Once initialised, the middleware will validate incoming tokens, reject them if appropriate, and populate a `request.claimSet` object that can be used by downstream services.

```js
var tokenValidator = require('idcs-express-token-validator');

var tokenConfig = require('./idcs-config.json');

tokenValidator.initialise(tokenConfig);

var express = require('express');  
var app = express();

app.use(tokenValidator.validator);
```

## IDCS Setup

As of IDCS 17.3.4, IDCS now allows JWKs to be obtained without registering a client. This must be enabled by turning on 'Access Signing Certificate' in the Default Settings screen. If this is enabled, there is no need to configure an application in IDCS, or supply a client_id/secret in the configuration. 

If this is not enabled, this Middleware requires a Web Application to be configured in IDCS to support the Client Credential grant (to obtain the JWK Signing Keys). The client_id and secret of that application need to be provided in the configuration object detailed below.

In order to use scopes for authorisation, the token must have been issued for an IDCS application which is configured as a resource server with those scopes available.

## Configuration

A typical configuration object looks like the following:

```js
{
	"idcs_url":"https://<tenant_name>.idcs.<datacentre>.oraclecloud.com",
	"client_id":"<Application_Client_ID>",
	"client_secret":"<Application_Client_Secret>",

	"scopes_by_uri":{
		"/services/super-secret-info" : "super_secret",
		"/services/less-secret-info" : "less_secret",
		"/services/super-secret-personal-info" : "super_secret personal"
	}
}
```

### Associating Scopes with URIs

The scopes which were set up in IDCS can be used protect endpoints exposed through Express, though an association needs to be set up in the configuration which is used for initialisation. There are several ways to do this, the simplest being a URI:required scope mapping in the `scopes_by_uri` object.

Express named parameters are supported in this simple mapping, such that `/services/:serviceid` can be matched to scopes in the configuration.

Regex mapping of URIs is also supported, though requires an additional `regex_uris` array to be added to the configuration, which contains an array of regexes mapped to scopes. An example of this is:

```js
"regex_uris":[
		{"regex":"^\/services\/regular(-|_)info$", "scopes":"not_secret"}
	]
```

**Unknown URIS:** By default if a request comes on a path which cannot be matched, no scope validation is done. If the token is valid, it is considered a valid request. This can be overridden by setting a `default_scopes` value in the config. For instance, to perform a default deny on unknown paths:
```js
"default_scopes":"impossible_never_issued_scope"
```

At present there is no ability to set different required scopes for different HTTP methods. This perhaps could be added in a future release.

### Audience Validation

If validation of the 'aud' attribute of the token is required, simply add an `audience` value to the config object. This should match the Primary Audience configured in IDCS.
```js
"audience":"http://<host>:<port>/endpoint/"
```