// Load modules

var Boom = require('boom');
var Hoek = require('hoek');
var jwt = require('jsonwebtoken');
var Joi = require('joi');

var optionsSchema = Joi.object().keys({
  key: Joi.alternatives().try(Joi.binary(), Joi.func()).required(),
  validateFunc: Joi.func(),
  algorithms: Joi.array().items(Joi.string()),
  audience: Joi.alternatives().try(Joi.string(), Joi.array().items(Joi.string())),
  issuer: Joi.alternatives().try(Joi.string(), Joi.array().items(Joi.string())),
  subject: Joi.string()
}).label('jwt auth strategy options');

// Declare internals
var internals = {};

function register(server, options) {
  server.auth.scheme('jwt', internals.implementation);
};

function isFunction(functionToCheck) {
  const objectProto = Object.prototype.toString.call(functionToCheck);
  return objectProto === '[object Function]' || objectProto === '[object AsyncFunction]';
}

internals.implementation = function (server, options) {

  var validationResult = Joi.validate(options, optionsSchema);
  if (validationResult.error) {
    throw new Error(validationResult.error.message);
  }

  var settings = Hoek.clone(options);

  var scheme = {
    authenticate: async function (request, h) {

      var req = request.raw.req;
      var authorization = req.headers.authorization;
      if (!authorization) {
        throw Boom.unauthorized(null, 'Bearer');
      }

      var parts = authorization.split(/\s+/);

      if (parts.length !== 2) {
        throw Boom.badRequest('Bad HTTP authentication header format', 'Bearer');
      }

      if (parts[0].toLowerCase() !== 'bearer') {
        throw Boom.unauthorized(null, 'Bearer');
      }

      if (parts[1].split('.').length !== 3) {
        throw Boom.badRequest('Bad HTTP authentication header format', 'Bearer');
      }

      var token = parts[1];

      var getKey = isFunction(settings.key) ?
        settings.key :
        function (req, token) { return { key: settings.key }; };

      let keyResult;
      try {
        keyResult = await getKey(request, token);
      } catch (err) {
        throw err;
      }
      const { key, extraInfo } = keyResult;

      let decoded;
      try {
        decoded = jwt.verify(token, key, settings);
      } catch (err) {
        throw Boom.unauthorized('JSON Web Token validation failed: ' + err.message, 'Bearer');
      }

      if (!settings.validateFunc) {
        return h.authenticated({ credentials: decoded });
      }

      let validateResult;
      try {
        validateResult = await settings.validateFunc(decoded, extraInfo);
      } catch (err) {
        throw err;
      }

      const { isValid, credentials } = validateResult;

      if (!isValid) {
        throw Boom.unauthorized('Invalid token', 'Bearer');
      }

      if (!credentials || typeof credentials !== 'object') {
        throw Boom.badImplementation('Bad credentials object received for jwt auth validation');
      }

      // Authenticated
      return h.authenticated({ credentials: credentials });
    }
  };

  return scheme;
};

module.exports = {
  pkg: require('../package.json'),
  register,
}
