'use strict';

var session = require('../index'),
	assert = require('assert'),
	fs = require('fs');

describe('Testing Session', function () {

	var portNumber = 12345,
		opt, app, req, res;

	var initialize = function() {
		opt = {
			'isHTTPS': false,
			'session-env': true, 
			'session-key': 'mySecretKey',
			'session-name': 'my.sid',
			'peer2peer': '/cloud/session',
			'session-file': './session',
			'exp-time': 3600,
			'exp-interval': -1
		};
		app = {
			use: function() {
			},
			post: function(path, callback) {
				callback(req, res);
			}
		};
		res = {
			send: function() {
			},
			cookie: function() {
			}
		};
		req = {
			headers: {},
			sessionID: '54321',
			query: { action: 'TEST', sessionKey: opt['session-key'] }
		};
	};

	it('Should test session with default options', function(done) {
		initialize();
		session(app, portNumber, null);
		done();
	});

	it('Should test session with user options', function(done) {
		initialize();
		session(app, portNumber, opt);
		done();
	});

	it('Should test serialize JSON data', function(done) {
		initialize();
		var apis = session(app, portNumber, opt),
			data = apis.serialize();
		assert.equal(data, '""');
		data = apis.serialize(null, null, {'key':'value'});
		assert.equal(data, '{"key":"value"}');
		done();
	});

	it('Should test deserialize JSON data', function(done) {
		initialize();
		var apis = session(app, portNumber, opt),
			data = apis.deserialize();
		assert.ok(typeof data === 'object');
		data = apis.deserialize(null, null, '{"key":"value"}');
		assert.equal(data.key, 'value');
		done();
	});

	it('Should test encrypt token', function(done) {
		initialize();
		var apis = session(app, portNumber, opt),
			data = apis.encrypt ('df3c50b1c2eda61617457e5646e36f25', opt['session-key']);
		assert.equal(data, 'SzWSzd5DZiA9yrkMBhqgyPZU4CRaqC03xQp6mu1hXrg=');
		done();
	});

	it('Should test destroy current session', function(done) {
		initialize();
		var proxy = function() {
			return {
				request: function(callback) {
					callback(null);
				}
			};
		},
		apis = session(app, portNumber, opt, proxy);

		apis.destroy({ headers: {cookie: ''} });
		apis.destroy({ headers: {cookie: 'x-cloud-ipaddress=192.168.1.1'} }, function(err) {
			assert.equal(err, null);
			done();
		});
	});

	it('Should test post request without cookie', function(done) {
		initialize();
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};

		session(app, portNumber, opt);
		done();
	});

	it('Should test post request with invalid cookie', function(done) {
		initialize();
		req.headers.cookie = ' ';
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};

		session(app, portNumber, opt);
		done();
	});

	it('Should test post request with session id', function(done) {
		initialize();
		req.headers.cookie = opt['session-name'] + '=portNumber67890';
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test post transfer_sesssion action', function(done) {
		req.query.action = 'transfer_sesssion';
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test app middleware with existing session', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		app.use = function(callback) {
			_req.session = {};
			callback(_req, res, done);
		};
		session(app, portNumber, opt);
	});

	it('Should test app middleware with assigned sessionID', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		app.use = function(callback) {
			callback(_req, res, function() {
				done();
			});
		};
		session(app, portNumber, opt);
	});

	it('Should test app middleware without cookie', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		_req.sessionID = null;
		app.use = function(callback) {
			_req.headers.cookie = null;
			callback(_req, res, done);
		};
		session(app, portNumber, opt);
	});

	it('Should test app middleware with invalid cookie', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		_req.sessionID = null;
		app.use = function(callback) {
			_req.headers.cookie = ' ';
			callback(_req, res, done);
		};
		session(app, portNumber, opt);
	});

	it('Should test app middleware x-cloud-ipaddress', function(done) {
		var _req = JSON.parse(JSON.stringify(req)),
			proxy = function() {
				return {
					request: function(callback) {
						callback(null, {time: Date.now(), data: {}});
					}
				};
			};
		_req.headers.cookie += ';x-cloud-ipaddress=192.255.255.255';
		app.use = function(callback) {
			callback(_req, res, done);
		};
		session(app, portNumber, opt, proxy);
	});

	it('Should test app middleware x-cloud-ipaddress invalid session', function(done) {
		var _req = JSON.parse(JSON.stringify(req)),
			proxy = function() {
				return {
					request: function(callback) {
						callback();
					}
				};
			};
		_req.headers.cookie += ';x-cloud-ipaddress=192.255.255.255';
		_req.sessionID = null;
		app.use = function(callback) {
			callback(_req, res, done);
		};
		session(app, portNumber, opt, proxy);
	});

	it('Should test app middleware save session to file', function(done) {
		process.env.NODE_ENV = 'development';
		var _req = JSON.parse(JSON.stringify(req));
		_req.sessionID = null;
		fs.unlink(opt['session-file'], function() {
			app.use = function(callback) {
				callback(_req, res, done);
			};
			session(app, portNumber, opt);
		});
	});

	it('Should test app middleware read session from file', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		_req.sessionID = null;
		app.use = function(callback) {
			callback(_req, res, done);
		};
		session(app, portNumber, opt);
	});

	it('Should test get remote session with new sessionId', function(done) {
		var _req = JSON.parse(JSON.stringify(req)),
			proxy = function() {
				return {
					request: function(callback) {
						callback();
					}
				};
			};
		app.use = function(callback) {
			callback(_req, res, function() {});
		};
		var apis = session(app, portNumber, opt, proxy);
		apis.getSession(_req, '192.255.255.255', 'NEW_SESSION_ID', function() {
			done();
		});
	});

	it('Should test app middleware cleanAll function', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		app.use = function(callback) {
			callback(_req, res, function() {});
		};

		var apis = session(app, portNumber, opt);
		apis.cleanAll();
		done();
	});

	it('Should test post update_session action', function(done) {
		initialize();
		req.query.action = 'update_session';
		req.query.sessionID = req.sessionID;
		req.query.path = '/data/node1/node2/node3';
		req.query.value = 'Hello World';

		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		res.send = function(session) {
			assert.equal(session.data.node1.node2.node3, req.query.value);
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test post update_session action with invalid sessionID', function(done) {
		initialize();
		req.query.action = 'update_session';
		req.query.sessionID = 666;

		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		res.send = function(data) {
			assert.equal(data, null);
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test update remote session', function(done) {
		initialize();
		var proxy = function() {
			return {
				request: function(callback) {
					callback();
				}
			};
		};
		var apis = session(app, portNumber, opt, proxy);
		apis.updateSession(req, '192.255.255.255', req.sessionID, '/key1/key2', 'VALUE', function() {
			done();
		});
	});

	it('Should test app middleware expire session', function(done) {
		initialize();
		var apis = null;
		app.use = function(callback) {
			setTimeout(function() {
				apis.serialize = function(req, res, session) {
					session.time -= opt['exp-time'] * 1000;
					return JSON.stringify(session);
				},
				callback(req, res, done);
				apis.cleanAll();
			}, 1);				
		};
		apis = session(app, portNumber, opt);
	});
});