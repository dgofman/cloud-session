'use strict';

var crypto = require('crypto'),
	fs = require('fs'),
	debug = require('debug')('cloud-session:index'),
	dns = require('dns'),
	sessionStore = {},
	ipaddress;

var ACTION = {
	COPY: 'copy_session',
	TRANSFER: 'transfer_sesssion',
	DESTROY: 'destroy_session',
	UPDATE: 'update_session'
};

dns.lookup(require('os').hostname(), function (err, ip) {
	/* istanbul ignore next */
	if (!err) {
		ipaddress = ip;
	} else {
		console.error(err);
	}
});

module.exports = function(app, portNumber, opt, proxy) {
	opt = opt || {};
	proxy = proxy || require('proxy-orchestrator');
	var apis = {},
		isHTTPS = !!opt.isHTTPS,
		isEnvSession = !!opt['session-env'] && ((process.env.NODE_ENV || '').trim() === 'development'),
		encryptKey = opt['encrypt-key'] || 'cl0udS3sS10nK3y',
		sessionName =  opt['session-name'] || 'x-cloud-session',
		expTime = opt['exp-time'] || 3600, //session expiration time in seconds
		expInterval = opt['exp-interval'] || 60 * 10, //check exired sessions every 10 minutes
		peer2peer = opt['peer2peer'] || '/cloud-session',
		lastSessionFile = opt['session-file'] || './session',
		excludeBase = (typeof opt['exclude-base'] === 'string' ? [opt['exclude-base']] : opt['exclude-base'] || []),
		lastSessionId = null,
		sidRegExp = new RegExp(sessionName + '=([^;]+)');

	var request = function(req, data, query, next, host) {
		var token = apis.getToken(req);
		if (token) {
			var ip_id = token.split('|');
			if (!data.uid) {
				data.uid = ip_id[1];
			}
			debug('Request:host=' + ip_id[0] + ', uid=' + data.uid);
			proxy({
				host: host || ip_id[0],
				port: portNumber,
				secure: isHTTPS
			}, req).request(function(err, result) {
				next(err, result);
			}, 'POST', peer2peer, data, query);
		} else {
			next({error: 'Invalid Token'});
		}
	};

	opt.intercept = opt.intercept || function() {
	};

	apis.serialize = opt.serialize || function(req, res, data) {
		opt.intercept('SERIALIZE', req, data);
		return JSON.stringify(data || '');
	};

	apis.deserialize = opt.deserialize || function(req, res, data) {
		opt.intercept('DESERIALIZE', req, data);
		return JSON.parse(data || '{}');
	};

	apis.encrypt = opt.encrypt || function(val, secret) {
		opt.intercept('ENCRYPT', val, secret);
		return crypto.createHmac('sha256', secret).update(val).digest('base64');
	};

	apis.getToken = opt.getToken || function(req) {
		var token = null;
		if (req && req.headers) {
			token = req.headers[sessionName];
			if (!token) {
				var match = sidRegExp.exec(req.headers.cookie);
				if (match && match.length > 1) {
					token = global.unescape(match[1]);
				}
			}
		}
		if (token && token.split('|').length === 2) {
			return token;
		} else {
			return null;
		}
	};

	apis.createCookie = opt.createCookie || function(res, key, value) {
		res.cookie(key, value);
	},

	apis.cleanAll = opt.cleanAll || function() {
		var now = Date.now();
		for (var sessionId in sessionStore) {
			if (now - sessionStore[sessionId].time > (expTime * 1000)) {
				opt.intercept('DESTROY_SESSION', sessionId, sessionStore[sessionId]);
				debug('Destroy sessionId: ' + sessionId);
				/* istanbul ignore next */ 
				if (sessionId === lastSessionId) {
					fs.unlink(lastSessionFile);
				}
				delete sessionStore[sessionId];
			}
		}
	};

	apis.destroy = opt.destroy || function(req, next) {
		opt.intercept('DESTROY', req);
		request(req, {}, {action: ACTION.DESTROY}, next);
	};

	apis.getSession = function(req, sessionID, next) {
		opt.intercept('GET_SESSION', req, sessionID);
		request(req, {}, {action: ACTION[opt.action] || ACTION.TRANSFER}, function(err, result) {
			var session = result || {};
			sessionStore[sessionID] = sessionStore[sessionID] || {};
			sessionStore[sessionID].data = session;
			req.session = session;
			next(err, session);
		});
	},

	apis.updateSession = function(req, host, data, next) {
		opt.intercept('UPDATE_SESSION', req, host, data);
		debug('updateSession:host:' + host + ', data: ' + JSON.stringify(data));
		request(req, data, {action: ACTION.UPDATE}, next, host);
	},

	apis.next = function(err, req, res, next) {
		opt.intercept('NEXT', err);
		next(err);
	},

	app.post(peer2peer, function (req, res) {
		var sessionID = apis.encrypt(req.body.uid, encryptKey),
			sessionData = sessionStore[sessionID],
			data = null;

		if (!sessionData) {
			var token = apis.getToken(req);
			if (token) {
				sessionID = apis.encrypt(token.split('|')[1], encryptKey);
				sessionData = sessionStore[sessionID];
			}
		}

		debug('Host:' + req.headers.host + ', action: ' + req.query.action, ', sessionID: ' + sessionID);
		if (sessionData) {
			if (req.query.action === ACTION.UPDATE) {
				data = sessionData.data;
				try {
					for (var path in req.body) {	
						var node = sessionData.data, 
							arr = path.split('/');
						for (var i = 1; i < arr.length; i++) {
							var key = arr[i];

							if (i === arr.length - 1) {
								node[key] = req.body[path];
							} else {
								if (node[key] === undefined) {
									node[key] = {};
								}
								node = node[key];
							}
						}
					}
				} catch(e) {
					/* istanbul ignore next */ 
					debug(e.stack);
				}
			} else if (req.query.action === ACTION.COPY || req.query.action === ACTION.TRANSFER) {
				try {
					data = apis.serialize(req, res, sessionStore[sessionID].data);
				} catch(e) {
					/* istanbul ignore next */ 
					debug(e.stack);
				}
			}

			if (req.query.action === ACTION.DESTROY || req.query.action === ACTION.TRANSFER) {
				delete sessionStore[sessionID];
			}
		}
		res.send(data);
	});

	app.use(function session(req, res, next) {
		if (req.session) {
			return apis.next(null, req, res, next);
		} else {
			req.session = {};
		}

		for (var i in excludeBase) {
			if (req.path.indexOf(excludeBase[i]) === 0) {
				return apis.next(null, req, res, next);
			}
		}

		debug(req.path);

		var token = apis.getToken(req),
			sessionID = null;

		if (token) {
			var ip_id = token.split('|');
			sessionID = apis.encrypt(ip_id[1], encryptKey);
			try {
				if (isEnvSession && !sessionStore[sessionID] && fs.existsSync(lastSessionFile)) {
					sessionStore[sessionID] = apis.deserialize(req, res, fs.readFileSync(lastSessionFile, 'utf8'));
				}
			} catch(e) {
				/* istanbul ignore next */
				console.error(e.stack);
			}
		}

		if (!sessionID) {
			var uid = crypto.randomBytes(32).toString('hex').slice(0, 32);
			token = ipaddress + '|' + uid;
			apis.createCookie(res, sessionName, token);
			sessionID = apis.encrypt(uid, encryptKey);
		}

		sessionStore[sessionID] = sessionStore[sessionID] || {
			time: null,
			data: {}
		};

		sessionStore[sessionID].time = Date.now();

		if (isEnvSession) {
			lastSessionId = sessionID;
			fs.writeFileSync(lastSessionFile, apis.serialize(req, res, sessionStore[sessionID]));
		}

		if (token.split('|')[0] !== ipaddress) {
			apis.getSession(req, sessionID, function(err) {
				apis.next(err, req, res, next);
			});
		} else {
			req.session = sessionStore[sessionID].data;
			apis.next(null, req, res, next);
		}
	});

	//clean session storage on local machine 
	opt.intercept('START_INTERVAL', expInterval);
	if (expInterval !== -1) {
		setInterval(apis.cleanAll, expInterval * 1000);
	}

	return apis;
};

module.exports.ACTION = ACTION;