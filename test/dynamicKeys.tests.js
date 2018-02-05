// Load modules

var Lab  = require('lab');
var Hapi = require('hapi');
var Code = require('code');
var Hoek = require('hoek');
var Boom = require('boom');
var jwt  = require('jsonwebtoken');


// Test shortcuts

var lab = exports.lab = Lab.script();
var expect = Code.expect;
var before = lab.before;
var describe = lab.describe;
var it = lab.it;

describe('Dynamic Secret', function () {
  var keys = {
    'john': 'johnkey',
    'jane': 'janekey'
  };

  var info = {
    'john': 'johninfo',
    'jane': 'janeinfo',
  };

  var tokenHeader = function (username, options) {
    if (!keys[username]){
      throw new Error('Invalid user name ' + username + '. Valid options \'john\' or \'jane\'');
    }

    options = options || {};

    return 'Bearer ' + jwt.sign({username: username}, keys[username], options);
  };

  var tokenHandler = function (request, h) {
    return request.auth.credentials.username;
  };

  var getKey = async function(req, token){
    getKey.lastToken = token;
    var data = jwt.decode(token);

    return {
      key: keys[data.username],
      extraInfo: info[data.username]
    }
  };

  var validateFunc = function(decoded, extraInfo){
    validateFunc.lastExtraInfo = extraInfo;

    return {
      isValid: true,
      credentials: decoded
    };
  };

  var errorGetKey = function(req, token){
    throw new Error('Failed');
  };

  var boomErrorGetKey = function(req, token){
    throw Boom.forbidden('forbidden');
  };

  var server = new Hapi.Server({ debug: false });

  before(async function () {
    await server.register(require('../'))
    server.auth.strategy('normalError', 'jwt', { key: errorGetKey });
    server.auth.strategy('boomError', 'jwt', { key: boomErrorGetKey });
    server.auth.strategy('default', 'jwt', { key: getKey, validateFunc: validateFunc });
    server.route([
      { method: 'POST', path: '/token', handler: tokenHandler, config: { auth: 'default' } },
      { method: 'POST', path: '/normalError', handler: tokenHandler, config: { auth: 'normalError' } },
      { method: 'POST', path: '/boomError', handler: tokenHandler, config: { auth: 'boomError' } }
    ]);
  });

  ['jane', 'john'].forEach(function(user){

    it('uses key function passing ' + user + '\'s token if ' + user + ' is user', async function () {

      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader(user) } };

      var res = await server.inject(request);
      expect(res.result).to.exist;
      expect(res.result).to.equal(user);

      const decoded = await jwt.verify(getKey.lastToken, keys[user]);
      expect(decoded.username).to.equal(user);

    });

    it('uses validateFunc function passing ' + user + '\'s extra info if ' + user + ' is user', async function () {

      var request = { method: 'POST', url: '/token', headers: { authorization: tokenHeader(user) } };

      const res = await server.inject(request);

      expect(res.result).to.exist;
      expect(res.result).to.equal(user);

      expect(validateFunc.lastExtraInfo).to.equal(info[user]);
    });
  });

  it('return 500 if an is error thrown when getting key', async function(){

    var request = { method: 'POST', url: '/normalError', headers: { authorization: tokenHeader('john') } };

    var res = await server.inject(request);
    expect(res).to.exist;
    expect(res.result.statusCode).to.equal(500);
    expect(res.result.error).to.equal('Internal Server Error');
    expect(res.result.message).to.equal('An internal server error occurred');
  });

  it('return 403 if an is error thrown when getting key', async function(){

    var request = { method: 'POST', url: '/boomError', headers: { authorization: tokenHeader('john') } };
    var res = await server.inject(request);
    expect(res).to.exist;
    expect(res.result.statusCode).to.equal(403);
    expect(res.result.error).to.equal('Forbidden');
    expect(res.result.message).to.equal('forbidden');
  });
});
