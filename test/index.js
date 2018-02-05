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

  var loadUser = function (decodedToken) {
    var username = decodedToken.username;

    if (username === 'john') {
      return {
        isValid: true,
        credentials: {user: 'john', scope: ['a'] }
      };
    } else if (username === 'jane') {
      throw Boom.badImplementation();
    } else if (username === 'invalid1') {
      return {
        isValid: true,
        credentials: 'bad'
      };
    } else if (username === 'nullman') {
      return {
        isValid: true,
        credentials: null,
      };
    }
    return {
      isValid: false,
    };
  };

  var tokenHandler = () => 'ok';

  var doubleHandler = async function (request, h) {
    var options = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') }, credentials: request.auth.credentials };
    var res = await server.inject(options);

    return res.result;
  };

  var server = new Hapi.Server({ debug: false });

  before(async function () {

    await server.register(require('../'))
    server.auth.strategy('default', 'jwt', { key: privateKey,  validateFunc: loadUser });
    server.auth.default('default');

    server.route([
      { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } },
      { method: 'POST', path: '/tokenOptional', handler: tokenHandler, config: { auth: { mode: 'optional' } } },
      { method: 'POST', path: '/tokenScope', handler: tokenHandler, config: { auth: { scope: 'x' } } },
      { method: 'POST', path: '/tokenArrayScope', handler: tokenHandler, config: { auth: { scope: ['x', 'y'] } } },
      { method: 'POST', path: '/tokenArrayScopeA', handler: tokenHandler, config: { auth: { scope: ['x', 'y', 'a'] } } },
      { method: 'POST', path: '/double', handler: doubleHandler }
    ]);

    await server.start();
  });

  it('returns a reply on successful auth', async function () {
    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

    var res = await server.inject(request);
    expect(res.result).to.exist;
    expect(res.result).to.equal('ok');
  });

  it('returns decoded token when no validation function is set', async function () {

    var handler = function (request) {
      expect(request.auth.isAuthenticated).to.equal(true);
      expect(request.auth.credentials).to.exist;
      return 'ok';
    };

    var server = new Hapi.Server({ debug: false });
    await server.register(require('../'));

    server.auth.strategy('default', 'jwt', { key: privateKey });
    server.route([
      { method: 'POST', path: '/token', handler: handler, config: { auth: 'default' } }
    ]);

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

    const res = await server.inject(request);
    expect(res.result).to.exist;
    expect(res.result).to.equal('ok');
  });

  it('returns an error on wrong scheme', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'Steve something' } };
    const res = await server.inject(request)

    expect(res.statusCode).to.equal(401);
  });

  it('returns a reply on successful double auth', async function () {

    var request = { method: 'POST', url: '/double', headers: { authorization: tokenHeader('john') } };

    const res = await server.inject(request);
    expect(res.result).to.exist;
    expect(res.result).to.equal('ok');

  });

  it('returns a reply on failed optional auth', async function () {

    var request = { method: 'POST', url: '/tokenOptional' };

    const res = await server.inject(request);
    expect(res.result).to.equal('ok');
  });

  it('returns an error with expired token', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', { expiresIn: -10 }) } };

    const res = await server.inject(request);
    expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt expired');
    expect(res.statusCode).to.equal(401);

  });

  it('returns an error with invalid token', async function () {
    var token = tokenHeader('john') + '123456123123';

    var request = { method: 'POST', url: '/token', headers: { authorization: token } };

    const res = await server.inject(request);
    expect(res.result.message).to.equal(jwtErrorPrefix + 'invalid signature');
    expect(res.statusCode).to.equal(401);
  });

  it('returns an error on bad header format', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'Bearer' } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(400);
    expect(res.result.isMissing).to.equal(undefined);

  });

  it('returns an error on bad header format', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'bearer' } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(400);
    expect(res.result.isMissing).to.equal(undefined);
  });

  it('returns an error on bad header internal syntax', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: 'bearer 123' } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(400);
    expect(res.result.isMissing).to.equal(undefined);
  });

  it('returns an error on unknown user', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('doe') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(401);
  });

  it('returns an error on internal user lookup error', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('jane') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(500);
  });

  it('returns an error on non-object credentials error', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('invalid1') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(500);
  });

  it('returns an error on null credentials error', async function () {

    var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('nullman') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(500);
  });

  it('returns an error on insufficient scope', async function () {

    var request = { method: 'POST', url: '/tokenScope', headers: { authorization: tokenHeader('john') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(403);
  });

  it('returns an error on insufficient scope specified as an array', async function () {

    var request = { method: 'POST', url: '/tokenArrayScope', headers: { authorization: tokenHeader('john') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(403);

  });

  it('authenticates scope specified as an array', async function () {

    var request = { method: 'POST', url: '/tokenArrayScopeA', headers: { authorization: tokenHeader('john') } };

    const res = await server.inject(request);

    expect(res.result).to.exist;
    expect(res.statusCode).to.equal(200);
  });

  it('cannot add a route that has payload validation required', async function () {

    var fn = function () {
      server.route({ method: 'POST', path: '/tokenPayload', handler: tokenHandler, config: { auth: { mode: 'required', payload: 'required' } } });
    };

    expect(fn).to.throw(Error);
  });

  describe('when a single audience is specified for validation', async function(){
    var audience = 'https://expected.audience.com';
    var newServer = new Hapi.Server({ debug: false });

    before(async function () {

      await newServer .register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, audience: audience});
      newServer.auth.default('default');

      newServer .route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer .start();
    });

    it('fails if token audience is empty', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience);
      expect(res.statusCode).to.equal(401);
    });

    it('fails if token audience is invalid', async function () {

      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience:'https://invalid.audience.com'}) } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience);
      expect(res.statusCode).to.equal(401);
    });

    it('works if token audience is valid', async function () {

      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience: audience}) } };

      const res = await newServer.inject(request);
      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
    });
  });

  describe('when an array of audiences is specified for validation', function(){
    var audience = 'https://expected.audience.com';

    var newServer = new Hapi.Server({ debug: false });

    before(async function () {
      await newServer.register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, audience: [audience, 'audience2', 'audience3']});
      newServer.auth.default('default');

      newServer.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer.start();
    });

    it('fails if token audience is empty', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience + ' or audience2 or audience3');
      expect(res.statusCode).to.equal(401);
    });

    it('fails if token audience is invalid', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience:'https://invalid.audience.com'}) } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt audience invalid. expected: ' + audience + ' or audience2 or audience3');
      expect(res.statusCode).to.equal(401);
    });

    it('works if token audience is one of the expected values', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {audience: audience}) } };

      const res = await newServer.inject(request);
      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
    });

  });

  describe('when a single issuer is specified for validation', function(){
    var issuer = 'http://expected.issuer';

    var newServer = new Hapi.Server({ debug: false });

    before(async function () {
      await newServer.register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, issuer: issuer});
      newServer.auth.default('default');

      newServer.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer.start();
    });

    it('fails if token issuer is empty', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer);
      expect(res.statusCode).to.equal(401);
    });

    it('fails if token issuer is invalid', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer:'https://invalid.issuer'}) } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer);
      expect(res.statusCode).to.equal(401);
    });

    it('works if token issuer is valid', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer: issuer}) } };

      const res = await newServer.inject(request);
      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
    });

  });

  describe('when an array of issuers are specified for validation', function(){
    var issuer = 'http://expected.issuer';

    var newServer = new Hapi.Server({ debug: false });
    newServer.log(['error', 'database', 'read']);

    before(async function () {
      await newServer.register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, issuer: [issuer,'issuer2','issuer3']});
      newServer.auth.default('default');

      newServer.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer.start();
    });

    it('fails if token issuer is empty', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer + ',issuer2,issuer3');
      expect(res.statusCode).to.equal(401);
    });

    it('fails if token issuer is invalid', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer:'https://invalid.issuer'}) } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt issuer invalid. expected: ' + issuer + ',issuer2,issuer3');
      expect(res.statusCode).to.equal(401);
      });

    it('works if token issuer contains one of the expected issuers valid', async function () {

      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {issuer: issuer}) } };

      const res = await newServer.inject(request);
      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
    });

  });

  describe('when RS256 is specified as algorithm for validation', function(){
    var newServer = new Hapi.Server({ debug: false });

    before(async function () {
      await newServer.register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, algorithms: ['RS256'] });
      newServer.auth.default('default');

      newServer.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer.start();
    });

    it('fails if token is signed with HS256 algorithm', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'invalid algorithm');
      expect(res.statusCode).to.equal(401);
    });
  });

  describe('when HS256 is specified as algorithm for validation', function(){
    var newServer = new Hapi.Server({ debug: false });

    before(async function () {
      await newServer.register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, algorithms: ['HS256'] });
      newServer.auth.default('default');

      newServer.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer.start();
    });

    it('works if token is signed with HS256 algorithm', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
    });
  });

  describe('when subject is specified for validation', function(){
    var subject = 'http://expected.subject';

    var newServer = new Hapi.Server({ debug: false });

    before(async function () {
      await newServer.register(require('../'))
      newServer.auth.strategy('default', 'jwt', { key: privateKey, validateFunc: loadUser, subject: subject });
      newServer.auth.default('default');

      newServer.route([
        { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } }
      ]);

      await newServer.start();
    });

    it('fails if token subject is empty', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john') } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt subject invalid. expected: ' + subject);
      expect(res.statusCode).to.equal(401);
    });

    it('fails if token subject is invalid', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {subject:'https://invalid.subject'}) } };

      const res = await newServer.inject(request);
      expect(res.result.message).to.equal(jwtErrorPrefix + 'jwt subject invalid. expected: ' + subject);
      expect(res.statusCode).to.equal(401);
    });

    it('works if token subject is valid', async function () {
      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader('john', {subject: subject}) } };

      const res = await newServer.inject(request);
      expect(res.result).to.exist;
      expect(res.statusCode).to.equal(200);
    });

  });

});

describe('Strategy', function(){

  it('should fail if strategy is initialized without options', async function () {
    var server = new Hapi.Server({ debug: false });
    await server.register(require('../'))
    try {
      server.auth.strategy('default', 'jwt', null);
    }
    catch(err){
      expect(err).to.exist;
      expect(err.message).to.equal('"jwt auth strategy options" must be an object');
    }
  });

  it('should fail if strategy is initialized with a string as options', async function () {
    var server = new Hapi.Server({ debug: false });
    await server.register(require('../'))
    try {
      server.auth.strategy('default', 'jwt', 'wrong options type');
    }
    catch(err){
      expect(err).to.exist;
      expect(err.message).to.equal('options must be an object');
    }
  });


  it('should fail if strategy is initialized with an array as options', async function () {
    var server = new Hapi.Server({ debug: false });
    await server.register(require('../'))
    try {
      server.auth.strategy('default', 'jwt', ['wrong', 'options', 'type']);
     }
    catch(err){
      expect(err).to.exist;
      expect(err.message).to.equal('"jwt auth strategy options" must be an object');
    }
  });

  it('should fail if strategy is initialized with a function as options', async function () {
    var server = new Hapi.Server({ debug: false });

    await server.register(require('../'))
    try {
      server.auth.strategy('default', 'jwt', function options(){});
    }
    catch(err){
      expect(err).to.exist;
      expect(err.message).to.equal('options must be an object');
    }
  });

  it('should fail if strategy is initialized without a key in options', async function () {
    var server = new Hapi.Server({ debug: false });
    await server.register(require('../'));
    try {
      server.auth.strategy('default', 'jwt', {});
    }
    catch(err){
      expect(err).to.exist;
      expect(err.message).to.equal('child "key" fails because ["key" is required]');
    }
  });


  it('should fail if strategy is initialized with an invalid key type in options', async function () {
    var server = new Hapi.Server({ debug: false  });
    await server.register(require('../'));
    try {
      server.auth.strategy('default', 'jwt', {key:10});
    }
    catch(err){
      expect(err.message).to.equal('child "key" fails because ["key" must be a buffer or a string, "key" must be a Function]');
    }
  });

  it('should work if strategy is initialized with a Bugger as key in options', async function () {
    var server = new Hapi.Server({ debug: false  });
    await server.register(require('../'));
    try {
      server.auth.strategy('default', 'jwt', {key: new Buffer('mySuperSecret', 'base64')});
    } catch (e) {
      Code.fail('This should not occur');
    }
  });

  it('should fail if strategy is initialized with an invalid audience type in options', async function () {
    var server = new Hapi.Server({ debug: false });
    await server.register(require('../'));
    try {
      server.auth.strategy('default', 'jwt', {key: '123456', audience: 123});
    }
    catch(err){
      expect(err).to.exist;
      expect(err.message).to.equal('child "audience" fails because ["audience" must be a string, "audience" must be an array]');
    }
  });
});
