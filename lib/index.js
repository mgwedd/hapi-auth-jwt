// Load modules

var Boom = require('boom');
var Hoek = require('hoek');
var jwt  = require('jsonwebtoken');
var Joi = require('joi');

var optionsSchema = Joi.object().keys({
  key: Joi.alternatives().try(Joi.string(),Joi.func()).required(),
  validateFunc: Joi.func(),
  algorithms: Joi.array().items(Joi.string()),
  audience: Joi.alternatives().try(Joi.string(),Joi.array().items(Joi.string())),
  issuer: Joi.alternatives().try(Joi.string(),Joi.array().items(Joi.string())),
  subject: Joi.string()
}).label('jwt auth strategy options');

// Declare internals
var internals = {};


exports.register = function (server, options, next) {

  server.auth.scheme('jwt', internals.implementation);
  next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

function isFunction(functionToCheck) {
  return Object.prototype.toString.call(functionToCheck) === '[object Function]';
}

internals.implementation = function (server, options) {

  var validationResult = Joi.validate(options, optionsSchema);

  if (validationResult.error){
    throw new Error(validationResult.error.message);
  }

  var settings = Hoek.clone(options);

  var scheme = {
    authenticate: function (request, reply) {

      var req = request.raw.req;
      var authorization = req.headers.authorization;
      if (!authorization) {
        return reply(Boom.unauthorized(null, 'Bearer'));
      }

      var parts = authorization.split(/\s+/);

      if (parts.length !== 2) {
        return reply(Boom.badRequest('Bad HTTP authentication header format', 'Bearer'));
      }

      if (parts[0].toLowerCase() !== 'bearer') {
        return reply(Boom.unauthorized(null, 'Bearer'));
      }

      if(parts[1].split('.').length !== 3) {
        return reply(Boom.badRequest('Bad HTTP authentication header format', 'Bearer'));
      }

      var token = parts[1];

      var getKey = isFunction(settings.key) ?
        settings.key :
        function(req, token, callback) { callback(null, settings.key); };

      getKey(request, token, function(err, key, extraInfo){
        if (err) { return reply(Boom.wrap(err)); }
        // handle err
        jwt.verify(token, key, settings, function(err, decoded) {
          
          if(err) {
            return reply(Boom.unauthorized( 'JSON Web Token validation failed: ' + err.message, 'Bearer'));
          }

          if (!settings.validateFunc) {
            return reply.continue({ credentials: decoded });
          }

          settings.validateFunc(decoded, extraInfo, function (err, isValid, credentials) {

            credentials = credentials || null;

            if (err) {
              return reply(err, null, { credentials: credentials, log: { tags: ['auth', 'jwt'], data: err } });
            }

            if (!isValid) {
              return reply(Boom.unauthorized('Invalid token', 'Bearer'), null, { credentials: credentials });
            }

            if (!credentials || typeof credentials !== 'object') {

              return reply(Boom.badImplementation('Bad credentials object received for jwt auth validation'), null, { log: { tags: 'credentials' } });
            }

            // Authenticated

            return reply.continue({ credentials: credentials });
          });

        });
      });
    }
  };

  return scheme;    

};
