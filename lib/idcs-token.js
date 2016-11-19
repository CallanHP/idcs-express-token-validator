/* 
 * Functions that connect to IDCS to obtain initialise the token middleware.
 */
var base64 = require('js-base64').Base64;
var request = require('request');

exports.getBearerToken = function(config, idcsAgent){
	return new Promise(function(resolve, reject){
		var bearer = "";
		var options = {
				method: "POST",
				url: config.idcs_url + config.token_url,
				headers: {
					"Authorization":"Basic " +base64.encode(config.client_id +":" +config.client_secret),
					"Content-Type":"application/x-www-form-urlencoded"
				},
				body: "grant_type=client_credentials"+"&scope=urn:opc:idm:__myscopes__",
				agent: idcsAgent
			};
		request(options, function(err, res, body){
			if(err){
				reject(err);
				return;
			}
			var bodyJson = JSON.parse(body);
			bearer = bodyJson["access_token"];
			if(bearer){
				resolve(bearer);
			}else{
				reject(new Error("Could not obtain Bearer token from IDCS!"));
			}
		});
	});
}

exports.getJWK = function(config, idcsAgent, bearerToken){
	return new Promise(function(resolve, reject){
		var options = {
				url: config.idcs_url + config.jwk_url,
				headers: {
					"Authorization":"Bearer " +bearerToken
				},
				agent: idcsAgent
			};
		request(options, function(err, res, body){
			if(err){
				reject(err);
				return;
			}
			resolve(JSON.parse(body));
		});
	});
}