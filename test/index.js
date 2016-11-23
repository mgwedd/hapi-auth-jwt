// Load modules

var Boom = require('boom');
var Code = require('code');
var Hapi = require('hapi');
var Jwt  = require('jsonwebtoken');
var Lab  = require('lab');


// Test shortcuts

var lab = exports.lab = Lab.script();
var before = lab.before;
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;

var jwtErrorPrefix = 'JSON Web Token validation failed: ';

describe('Token', function () {
  var privateKey = 'PajeH0mz4of85T9FB1oFzaB39lbNLbDbtCQ';

  var tokenHeader = function (username, options) {
    options = options || {};

    return 'Bearer ' + Jwt.sign({username : username}, privateKey, options);
  };

  var loadUser = function (decodedToken, _, callback) {
    var username = decodedToken.username;

    if (username === 'john') {
      return callback(null, true, {
        user: 'john',
        scope: ['a']
      });
    } else if (username === 'jane') {
      return callback(Boom.badImplementation());
    } else if (username === 'invalid1') {
      return callback(null, true, 'bad');
    } else if (username === 'nullman') {
      return callback(null, true, null);
    }

    return callback(null, false);
  };

  var tokenHandler = function (request, reply) {

    reply('ok');
  };

  var doubleHandler = function (request, reply) {

    var options = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') }, credentials: request.auth.credentials };

    server.inject(options, function (res) {

      reply(res.result);
    });
  };

  var server = new Hapi.Server({ debug: false });
  server.connection();

  before(function (done) {

    server.register(require('../'), function (err) {

      expect(err).to.not.exist;
      server.auth.strategy('default', 'jwt', 'required', { key: privateKey,  validateFunc: loadUser});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } },
        { method: 'POST', path: '/tokenOptional', handler: tokenHandler, config: { auth: { mode: 'optional' } } },
        { method: 'POST', path: '/tokenScope', handler: tokenHandler, config: { auth: { scope: 'x' } } },
        { method: 'POST', path: '/tokenArrayScope', handler: tokenHandler, config: { auth: { scope: ['x', 'y'] } } },
        { method: 'POST', path: '/tokenArrayScopeA', handler: tokenHandler, config: { auth: { scope: ['x', 'y', 'a'] } } },
        { method: 'POST', path: '/double', handler: doubleHandler }
      ]);

      done();
    });
  });

  it('returns a reply on successful auth', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.result).to.equal('ok');
      done();
    });
  });

  it('returns decoded token when no validation function is set', function (done) {

    var handler = function (request, reply) {
      expect(request.auth.isAuthenticated).to.equal(true);
      expect(request.auth.credentials).to.exist;
      reply('ok');
    };

    var server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey });

      server.route([
        { method: 'POST', path: '/token', handler: handler, config: { auth: 'default' } }
      ]);
    });

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.result).to.equal('ok');
      done();
    });
  });

  it('returns an error on wrong scheme', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'Steve something' } };

    server.inject(request, function (res) {

      expect(res.statusCode).to.equal(401);
      done();
    });
  });

  it('returns a reply on successful double auth', function (done) {

    var request = { method: 'POST', url: '/double', headers: { authorization: tokenHeader('john') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.result).to.equal('ok');
      done();
    });
  });

  it('returns a reply on failed optional auth', function (done) {

    var request = { method: 'POST', url: '/tokenOptional' };

    server.inject(request, function (res) {

      expect(res.result).to.equal('ok');
      done();
    });
  });

  it('returns an error with expired token', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', { expiresIn: -10 }) } };

    server.inject(request, function (res) {
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt expired');
      expect(res.statusCode).to.equal(401);
      done();
    });
  });

  it('returns an error with invalid token', function (done) {
    var token = tokenHeader('john') + '123456123123';

    var request = { method: 'POST', url: '/token', headers: { authorization: token } };

    server.inject(request, function (res) {
      expect(res.result.message).to.equal(jwtErrorPrefix + 'invalid signature');
      expect(res.statusCode).to.equal(401);
      done();
    });
  });

  it('returns an error on bad header format', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'Bearer' } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(400);
      expect(res.result.isMissing).to.equal(undefined);
      done();
    });
  });

  it('returns an error on bad header format', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'bearer' } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(400);
      expect(res.result.isMissing).to.equal(undefined);
      done();
    });
  });

  it('returns an error on bad header internal syntax', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'bearer 123' } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(400);
      expect(res.result.isMissing).to.equal(undefined);
      done();
    });
  });

  it('returns an error on unknown user', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('doe') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(401);
      done();
    });
  });

  it('returns an error on internal user lookup error', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('jane') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(500);
      done();
    });
  });

  it('returns an error on non-object credentials error', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('invalid1') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(500);
      done();
    });
  });

  it('returns an error on null credentials error', function (done) {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('nullman') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(500);
      done();
    });
  });

  it('returns an error on insufficient scope', function (done) {

    var request = { method: 'POST', url: '/tokenScope', headers: { authorization: tokenHeader('john') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(403);
      done();
    });
  });

  it('returns an error on insufficient scope specified as an array', function (done) {

    var request = { method: 'POST', url: '/tokenArrayScope', headers: { authorization: tokenHeader('john') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(403);
      done();
    });
  });

  it('authenticates scope specified as an array', function (done) {

    var request = { method: 'POST', url: '/tokenArrayScopeA', headers: { authorization: tokenHeader('john') } };

    server.inject(request, function (res) {

      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
      done();
    });
  });

  it('cannot add a route that has payload validation required', function (done) {

    var fn = function () {

      server.route({ method: 'POST', path: '/tokenPayload', handler: tokenHandler, config: { auth: { mode: 'required', payload: 'required' } } });
    };

    expect(fn).to.throw(Error);
    done();
  });

  describe('when a single audience is specified for validation', function(){
    var audience = 'https://expected.audience.com'; 

    var server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, audience: audience});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('fails if token audience is empty', function (done) {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience);
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('fails if token audience is invalid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience:'https://invalid.audience.com'}) } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience);
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('works if token audience is valid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience: audience}) } };

      server.inject(request, function (res) {
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
      });
    });

  });

  describe('when an array of audiences is specified for validation', function(){
    var audience = 'https://expected.audience.com'; 

    var server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, audience: [audience, 'audience2', 'audience3']});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('fails if token audience is empty', function (done) {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience + ' or audience2 or audience3');
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('fails if token audience is invalid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience:'https://invalid.audience.com'}) } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience + ' or audience2 or audience3');
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('works if token audience is one of the expected values', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience: audience}) } };

      server.inject(request, function (res) {
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
      });
    });

  });

  describe('when a single issuer is specified for validation', function(){
    var issuer = 'http://expected.issuer'; 
    
    var server = new Hapi.Server({ debug: false});
    server.log(['error', 'database', 'read']);
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, issuer: issuer});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('fails if token issuer is empty', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer);
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('fails if token issuer is invalid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer:'https://invalid.issuer'}) } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer);
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('works if token issuer is valid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer: issuer}) } };

      server.inject(request, function (res) {
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
      });
    });

  });

  describe('when an array of issuers are specified for validation', function(){
    var issuer = 'http://expected.issuer'; 
    
    var server = new Hapi.Server({ debug: false});
    server.log(['error', 'database', 'read']);
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, issuer: [issuer,'issuer2','issuer3']});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('fails if token issuer is empty', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer + ',issuer2,issuer3');
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('fails if token issuer is invalid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer:'https://invalid.issuer'}) } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer + ',issuer2,issuer3');
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('works if token issuer contains one of the expected issuers valid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer: issuer}) } };

      server.inject(request, function (res) {
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
      });
    });

  });

  describe('when RS256 is specified as algorithm for validation', function(){
    var issuer = 'http://expected.issuer'; 
    
    var server = new Hapi.Server({ debug: false});
    server.log(['error', 'database', 'read']);
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, algorithms: ['RS256']});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('fails if token is signed with HS256 algorithm', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'invalid algorithm');
        expect(res.statusCode).to.equal(401);
        done();
      });
    });
  });

  describe('when HS256 is specified as algorithm for validation', function(){
    var issuer = 'http://expected.issuer'; 
    
    var server = new Hapi.Server({ debug: false});
    server.log(['error', 'database', 'read']);
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, algorithms: ['HS256']});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('works if token is signed with HS256 algorithm', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
      });
    });
  });

  describe('when subject is specified for validation', function(){
    var subject = 'http://expected.subject'; 
    
    var server = new Hapi.Server({ debug: false});
    server.log(['error', 'database', 'read']);
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;

      server.auth.strategy('default', 'jwt', 'required', { key: privateKey, validateFunc: loadUser, subject: subject});

      server.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);
    });
    
    it('fails if token subject is empty', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt subject invalid. expected: ' + subject);
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('fails if token subject is invalid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {subject:'https://invalid.subject'}) } };

      server.inject(request, function (res) {
        expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt subject invalid. expected: ' + subject);
        expect(res.statusCode).to.equal(401);
        done();
      });
    });

    it('works if token subject is valid', function (done) {
  
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {subject: subject}) } };

      server.inject(request, function (res) {
        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
      });
    });

  });

});

describe('Strategy', function(){
    
  it('should fail if strategy is initialized without options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required');
        done('Should have failed')
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('"jwt auth strategy options" must be an object');
        done();
      }
    });
  });

  it('should fail if strategy is initialized with a string as options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', 'wrong options type');
        done('Should have failed')
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('"jwt auth strategy options" must be an object');
        done();
      }
    });
  });

  it('should fail if strategy is initialized with an array as options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', ['wrong', 'options', 'type']);
        done('Should have failed')
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('"jwt auth strategy options" must be an object');
        done();
      }
    });
  });

  it('should fail if strategy is initialized with a function as options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', function options(){});
        done('Should have failed')
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('"jwt auth strategy options" must be an object');
        done();
      }
    });
  });

  it('should fail if strategy is initialized without a key in options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', {});
        done(new Error('Should have failed without key in the options'))
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('child "key" fails because ["key" is required]');
        done();
      }
    });
  });

  it('should fail if strategy is initialized with an invalid key type in options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', {key:10});
        done(new Error('Should have failed with an invalid key type in options'))
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('child "key" fails because ["key" must be a buffer or a string, "key" must be a Function]');
        done();
      }
    });
  });

  it('should work if strategy is initialized with a Bugger as key in options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', {key: new Buffer('mySuperSecret', 'base64')});
        done();
      }
      catch(err){
        done(err);
      }
    });
  });

  it('should fail if strategy is initialized with an invalid audience type in options', function (done) {
    var server = new Hapi.Server({ debug: false  });
    server.connection();
    server.register(require('../'), function (err) {
      expect(err).to.not.exist;
      try {
        server.auth.strategy('default', 'jwt', 'required', {key: '123456', audience: 123});
        done(new Error('Should have failed with an invalid audience type in options'))
      }
      catch(err){
        expect(err).to.exist;
        expect(err.message).to.equal('child "audience" fails because ["audience" must be a string, "audience" must be an array]');
        done();
      }
    });
  });

});