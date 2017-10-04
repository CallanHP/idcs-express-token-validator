/* 
 * Functions that connect to IDCS to obtain initialise the token middleware.
 */
var request = require('request');

exports.getBearerToken = function(config, idcsAgent){
	return new Promise(function(resolve, reject){
		//Handle no client_id/secret, assume not-secured.
		if(!config.client_id || config.client_id.length === 0 ||
			!config.client_secret || config.client_secret.length === 0){
			resolve(null);
			return;
		}
		var bearer = "";
		var options = {
				method: "POST",
				url: config.idcs_url + config.token_url,
				headers: {
					"Authorization":"Basic " +Buffer.from(config.client_id +":" +config.client_secret).toString('base64'),
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
				headers: {},
				agent: idcsAgent
			};
		if(bearerToken){
			options.headers["Authorization"] = "Bearer " +bearerToken;
		}
		request(options, function(err, res, body){
			if(err){
				reject(err);
				return;
			}
			resolve(JSON.parse(body));
		});
	});
}