/* 
 * Express Middleware that validates access-tokens sent to these services.
 * Configurable via idcs-token-config.json, with appropriate scopes etc.
 */
var https = require('https');
var jwt = require('jsonwebtoken');

var idcs = require('./lib/idcs-token');

//IDCS may use multiple keys in the future, which would mean we should do key selection.
//At present only uses RS256, so we are going to ensure that is used (no spoofing with alg:"none" here!).
const ALGORITHM = "RS256";
const DEFAULT_JWK_URL = "/admin/v1/SigningCert/jwk";
const DEFAULT_TOKEN_URL = "/oauth2/v1/token";

//Error messages (future option to make these vars and configurable maybe?)
const ERR_NO_TOKEN="Invalid or unreadable token provided.";
const ERR_EXP_TOKEN="The supplied token has expired";
const ERR_WRONG_SCOPES="The supplied token has insufficent privileges to access this resource.";
const ERR_FAILED_TO_OBTAIN_JWK="Could not connect to authorization server, please wait a moment then try again.";
const WARN_FAILED_TO_OBTAIN_JWK="Attempt was made to validate a token before JWK was initialised. "
                    +"You may not have called initialise() or the module may still be waiting on a "
                    +"response from IDCS. If you continue to see this message, check your configuration."
const ERR_NO_KEY_FOR_ALG="No signing key for alg: " +ALGORITHM +" found in jwk obtained from IDCS!";
const ERR_NO_CONFIG="An attempt was made to initialise the idcs-access-token-validator without a configuration.";


//Awkwardly we need to tag the cert with BEGIN and END tags for jsonwebtoken to work...
const PRECERT = "-----BEGIN CERTIFICATE----- \n";
const POSTCERT = "\n-----END CERTIFICATE----- "


var verifyOptions = { "algorithms":[ALGORITHM]};
var jwk;
var jwtSigningKey;

/* 
 * On initiation, authorises itself with IDCS and fetches the appropriate 
 * signing key which is used to decode the tokens in the middleware
 */
module.exports.initialise = function(configuration){
    if(!configuration){
        throw new Error(ERR_NO_CONFIG);
    }
    //Set up the configuration
    config = configuration;

    if(!config.jwk_url){
        config.jwk_url = DEFAULT_JWK_URL;
    }
    if(!config.token_url){
        config.token_url = DEFAULT_TOKEN_URL;
    }
    if(!config.default_scopes){
        config.default_scopes = "";
    }

    // Transform URLs which use express parametised routes to regex matches so we can test them with req.path
    // The regex transformation is going to be simple:
    // - Add start/end anchors
    // - Escape forward slashes
    // - transform named parameter nodes into [^\/] (not forward slash) matches
    config._regex_uris = [];
    for(var uri in config.scopes_by_uri ){
        if(uri.match(/\/:[^\/]/)){
            var regexString = "^" +uri + "$";
            regexString = regexString.replace(/\/:[^\/]+/g, "/[^/]+")
            regexString = regexString.replace(/\//g, "\\/")
            config._regex_uris.push({"regex":new RegExp(regexString), "scopes":config.scopes_by_uri[uri]});
            config.scopes_by_uri[uri] = null;
        }
    }
    //Load any passed regex_uris into our internal regex uris list
    if(config.regex_uris){
        for(var i=0; i<config.regex_uris.length; i++){
            var regexUri = config.regex_uris[i];
            if(typeof regexUri.regex == "string"){
                regexUri.regex = new RegExp(regexUri.regex);
            }
            config._regex_uris.push(regexUri);
        }
    }

    //Allow the use of a request agent. This is used in my dev environment (which has the wrong certs...)
    var idcsAgentOptions = config.requestAgent;
    if(!idcsAgentOptions){
        idcsAgentOptions = {};
    }
    var idcsAgent = new https.Agent(idcsAgentOptions);
    //If an audience was set, we need to make sure it is used in the JWT verification steps
    if(config.audience){
        verifyOptions["audience"]=config.audience;
    }
    console.log("idcs-access-token-validator: Initialising - connecting to IDCS...");
    idcs.getBearerToken(config, idcsAgent).then(function(bearerToken){
        if(bearerToken){
            console.log("idcs-access-token-validator: Obtained Bearer Token.");
        }
        idcs.getJWK(config, idcsAgent, bearerToken).then(function(result){
            jwk = result;
            //Parse the RSA Public key which we use for JWT validation (uses the root of the x5c(chain))
            for(var i=0; i<jwk.keys.length; i++){
                if(jwk.keys[i].alg == ALGORITHM){
                    jwtSigningKey = PRECERT + jwk.keys[i].x5c[0] + POSTCERT;
                    break;
                }
            }
            if(!jwtSigningKey){
                throw new Error(ERR_NO_KEY_FOR_ALG)
            }
            console.log("idcs-access-token-validator: Obtained JWKs. Ready to validate requests.");
        });
    }, function(err){
        console.log(err);
    });
}


/*
 * Middleware filtering component
 */
module.exports.validator = function(req, res, next){
    //Do not validate on OPTION - I am not sure that this is good practice, 
    //which is why there is a config option, but it is needed to allows 
    //browsers to pass CORS (since they don't send the token on the initial OPTIONS call)
    if(req.method == "OPTIONS" && !config.validateOptions){
        next();
        return;
    }

    if(!jwk){
        console.log(WARN_FAILED_TO_OBTAIN_JWK);
        res.status(500).send(ERR_FAILED_TO_OBTAIN_JWK);
        return;
    }
    //Extract token
    var accessToken = req.get('Authorization');
    //Token should be in the form: Bearer <token>
    if(accessToken == undefined || !accessToken.startsWith("Bearer ")){
        //Respond 401 if no token
        res.status(401).send(ERR_NO_TOKEN);
        return;
    }
    accessToken = accessToken.substr("Bearer ".length);

    //Use JWT to validate
    var tokenPayload;
    try {
        //Verify the jwt signature
        tokenPayload = jwt.verify(accessToken, jwtSigningKey, verifyOptions);
    } catch(err) {
        if(err.name == "TokenExpiredError"){
            res.status(401).send(ERR_EXP_TOKEN);
        }else{
            res.status(401).send(ERR_NO_TOKEN);
        }
        return;
    }
    //Extract valid scopes
    var validScopes = "";
    if(tokenPayload.scope){
        validScopes = tokenPayload.scope;
    }
    //Validate scopes by URL
    //Attempt simple matching
    var requiredScopes;
    if(config.scopes_by_uri[req.path]){
        requiredScopes = config.scopes_by_uri[req.path];
    }else{
        //Need to do regex matching... yey...
        for(var i=0; i<config._regex_uris.length; i++){
            if(config._regex_uris[i].regex.test(req.path)){
                requiredScopes = config._regex_uris[i].scopes;
                break;
            }
        }
    }
    //Default to no scopes required if we couldn't match
    if(!requiredScopes){
        requiredScopes = config.default_scopes;
    }
    //Ensure that all of the required scopes are in the claimset
    requiredScopes = requiredScopes.split(" ");
    for(var i=0; i<requiredScopes.length; i++){
        var testRegex = "(^| )"+requiredScopes+"($| )"
        if(validScopes.search(new RegExp(testRegex)) == -1){
            res.status(401).send(ERR_WRONG_SCOPES);
            return;
        }
    }
    //Make the payload available in the req object.
    req.claimSet = tokenPayload;
    //If we have got through all of this... next()!
    next();
}


