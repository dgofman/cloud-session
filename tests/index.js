'use strict';

var session = require('../index'),
	assert = require('assert');

describe('Testing Session', function () {

	var portNumber = 12345,
		sessionName = 'my.sid',
		encryptKey = 'mySecretKey',
		opt, app, req, res;

	var initialize = function() {
		opt = {
			'isHTTPS': false,
			'session-env': true, 
			'encrypt-key': encryptKey,
			'session-name': sessionName,
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
			cookie: function(key, value) {
				req.headers.saved_cookies[key] = value;
			}
		};
		req = {
			body: {uid: '12345'},
			headers: {host: '127.0.0.1', saved_cookies: {}},
			sessionID: '54321',
			query: { action: 'TEST', sessionKey: encryptKey }
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

	it('Should test getToken without cookies and headers', function(done) {
		initialize();
		var token = session(app, portNumber, opt).getToken({});
		assert.equal(token, null);
		done();
	});

	it('Should test getToken from headers', function(done) {
		initialize();
		var token, headers = {};
		headers[sessionName] = '127.0.0.1|zzzz';
		token = session(app, portNumber, opt).getToken({headers: headers});
		assert.equal(token, '127.0.0.1|zzzz');
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
			data = apis.encrypt ('df3c50b1c2eda61617457e5646e36f25', encryptKey);
		assert.equal(data, 'SzWSzd5DZiA9yrkMBhqgyPZU4CRaqC03xQp6mu1hXrg=');
		apis.encrypt ('', encryptKey);
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

		apis.destroy({ headers: {cookie: ''} }, function(err) {
			assert.equal(err.error, 'Invalid Token');

			apis.destroy({ headers: {cookie: sessionName + '=127.0.0.1|0123456789'} }, function(err) {
				assert.equal(err, null);
				done();
			});
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

	it('Should test post request with invalid cookie token', function(done) {
		initialize();
		req.headers.cookie = sessionName + '=127.0.0.1';
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};

		session(app, portNumber, opt);
		done();
	});

	it('Should test post request with session id', function(done) {
		initialize();
		req.headers.cookie = sessionName + '=127.0.0.1|xxxxx';
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

	it('Should test app middleware with the same sessionID', function(done) {
		var _req = JSON.parse(JSON.stringify(req)),
			apis = null;
		app.use = function(callback) {
			setTimeout(function() {
				var token = _req.headers.saved_cookies[sessionName];
				_req.headers.cookie = sessionName + '=' + token;
				callback(_req, res, function() {
					assert.equal(_req.sessionID, apis.encrypt(token.split('|')[1], encryptKey));
					app.use = function(callback) {
						callback(_req, res, function() {
							done();
						});
					};
				});
				_req.session = null;
				session(app, portNumber, opt);
			}, 1);
		};
		apis = session(app, portNumber, opt);
	});

	it('Should test app middleware without cookie', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
		app.use = function(callback) {
			_req.headers.cookie = null;
			callback(_req, res, done);
		};
		session(app, portNumber, opt);
	});

	it('Should test app middleware with invalid cookie', function(done) {
		var _req = JSON.parse(JSON.stringify(req));
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
		_req.headers.cookie = sessionName + '=127.0.0.1|abc';
		app.use = function(callback) {
			callback(_req, res, done);
		};
		session(app, portNumber, opt, proxy);
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
		apis.getSession(_req, apis.encrypt('NEW_SESSION_ID', encryptKey), function() {
			done();
		});
	});

	it('Should test post update_session action', function(done) {
		initialize();
		req.query.action = session.ACTION.UPDATE;
		req.body = {
			'uid': 'NEW_SESSION_ID',
			'/node1/node2/node3': 'Hello',
			'/node1/node2/node4':  'World'
		};

		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		res.send = function(session) {
			assert.equal(session.node1.node2.node3, 'Hello');
			assert.equal(session.node1.node2.node4, 'World');
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test post copy_session action', function(done) {
		initialize();
		req.query.action = session.ACTION.COPY;
		req.body.uid = 'NEW_SESSION_ID';
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test post destroy_session action', function(done) {
		initialize();
		req.query.action = session.ACTION.DESTROY;
		req.body.uid = 'NEW_SESSION_ID';
		app.post = function(path, callback) {
			assert.equal(path, opt.peer2peer);
			callback(req, res);
		};
		session(app, portNumber, opt);
		done();
	});

	it('Should test netConnection call', function(done) {
		initialize();
		process.env.NODE_ENV = 'development';
		var apis = session(app, portNumber, opt);
		apis.netConnection('127.0.0.1', portNumber).on('error', function(err) {
			assert.equal(err.code, 'ECONNREFUSED');
			done();
		});
	});

	it('Should test custom netConnection', function(done) {
		initialize();
		process.env.NODE_ENV = 'development';
		opt['ping-timeout'] = 3000;
		var apis, lastHost = '127.1.2.3',
			_req = JSON.parse(JSON.stringify(req)),
			proxy = function() {
				return {
					request: function(callback) {
						callback(null, {time: Date.now(), data: {}});
					}
				};
			};
		_req.headers.cookie = sessionName + '=' + lastHost + '|' + Date.now();
		app.use = function(next) {
			setTimeout(function() {
				apis.netConnection = function(host, port, callback) {
					assert.equal(host, lastHost);
					assert.equal(port, portNumber);
					callback();
					return {
						setTimeout: function(pingTimeout, callback) {
							assert.equal(pingTimeout, opt['ping-timeout']);
							callback();
							done();
						}
					};
				};
				next(_req, res, function() {});
			}, 100);
		};
		apis = session(app, portNumber, opt, proxy);
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

	it('Should test update remote session', function(done) {
		initialize();
		var proxy = function() {
			return {
				request: function(callback) {
					callback();
				}
			};
		};
		var apis = session(app, portNumber, opt, proxy),
			_req = JSON.parse(JSON.stringify(req));
		_req.headers.cookie = sessionName + '=127.0.0.1|abc';
		apis.updateSession(_req, '192.255.255.255', {'uid': 'UPDATE_SESSION_ID', '/key1/key2': 'VALUE'}, function() {
			done();
		});
	});

	it('Should test app middleware expire session', function(done) {
		initialize();
		var apis = null;
		app.use = function(callback) {
			setTimeout(function() {
				apis.serialize = function(req, res, session) {
					session.time -= opt['exp-time'] * 10000;
					return JSON.stringify(session);
				},
				callback(req, res, done);
				apis.cleanAll();
			}, 1);				
		};
		apis = session(app, portNumber, opt);
	});

	it('Should test exclude static context', function(done) {
		initialize();
		opt['exclude-base'] = '/static';
		var _req = JSON.parse(JSON.stringify(req));
		_req.path = '/static/foo.png';
		app.use = function(callback) {
			callback(_req, res, function() {
				done();
			});
		};
		session(app, portNumber, opt);
	});

	it('Should test exclude non-static context', function(done) {
		initialize();
		opt['exclude-base'] = '/static';
		var _req = JSON.parse(JSON.stringify(req));
		_req.path = '/test';
		app.use = function(callback) {
			callback(_req, res, function() {
				done();
			});
		};
		session(app, portNumber, opt);
	});
});