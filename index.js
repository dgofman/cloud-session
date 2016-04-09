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
	DESTROY: 'destroy_session'
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
		sessionKey = opt['session-key'] || 'cl0udS3sS10nK3y',
		sessionName =  opt['session-name'] || 'x-cloud-session',
		expTime = opt['exp-time'] || 3600, //session expiration time in seconds
		expInterval = opt['exp-interval'] || 60 * 10, //check exired sessions every 10 minutes
		peer2peer = opt['peer2peer'] || '/cloud-session',
		lastSessionFile = opt['session-file'] || './session',
		lastSessionId = null,
		sidRegExp = new RegExp(sessionName + '=(\\w+)'),
		ipRegExp = new RegExp('x-cloud-ipaddress=([0-9|\.]+)');

	apis.serialize = opt.serialize || function(req, res, data) {
		return JSON.stringify(data || '');
	};

	apis.deserialize = opt.deserialize || function(req, res, data) {
		return JSON.parse(data || '{}');
	};

	apis.encrypt = opt.encrypt || function(val, secret) {
		return crypto.createHmac('sha256', secret).update(val).digest('base64');
	};

	apis.destroy = opt.destroy || function(req, callback) {
		var match = ipRegExp.exec(req.headers.cookie);
		if (match && match.length > 1) {
			proxy({
				host: match[1],
				port: portNumber,
				secure: isHTTPS
			}, req).request(callback, 'POST', peer2peer, {}, {sessionKey: sessionKey, action: ACTION.DESTROY});
		}
	};

	apis.cleanAll = opt.cleanAll || function() {
		var now = Date.now();
		for (var sessionId in sessionStore) {
			if (now - sessionStore[sessionId].time > (expTime * 1000)) {
				debug('Destroy sessionId: ' + sessionId);
				/* istanbul ignore next */ 
				if (sessionId === lastSessionId) {
					fs.unlink(lastSessionFile);
				}
				delete sessionStore[sessionId];
			}
		}
	};

	apis.getCookie = function(req, host, next) {
		debug('getCookie:host=' + host);
		proxy({
			host: host,
			port: portNumber,
			secure: isHTTPS
		}, req).request(function(err, result) {
			var session = result || {};
			/* istanbul ignore next */ 
			sessionStore[req.sessionID] = sessionStore[req.sessionID] || {};
			sessionStore[req.sessionID].data = session;
			req.session = session;
			next();
		}, 'POST', peer2peer, {}, {sessionKey: sessionKey, action: ACTION[opt.action] || ACTION.TRANSFER});
	},

	app.post(peer2peer, function (req, res) {
		var data = null;
		debug('Host:' + req.headers.host + ', action: ' + req.query.action + ', isvalid: ' + (req.query.sessionKey === sessionKey));
		if (req.headers && req.headers.cookie && req.query.sessionKey === sessionKey) {
			var match = sidRegExp.exec(req.headers.cookie);
			if (match && match.length > 1) {
				var sessionID = apis.encrypt(match[1], req.query.sessionKey);

				if (req.query.action === ACTION.COPY || req.query.action === ACTION.TRANSFER) {
					try {
						if (sessionStore[sessionID]) {
							data = apis.serialize(req, res, sessionStore[sessionID].data);
						}
					} catch(e) {
						/* istanbul ignore next */ 
						console.error(e.stack);
					}
				}

				if (req.query.action === ACTION.DESTROY || req.query.action === ACTION.TRANSFER) {
					delete sessionStore[sessionID];
				}
			}
		}
		res.send(data);
	});

	app.use(function session(req, res, next) {
		if (req.session) {
			return next();
		}

		if (!req.sessionID) {
			if (req.headers && req.headers.cookie) {
				var match = sidRegExp.exec(req.headers.cookie);
				if (match && match.length > 1) {
					try {
						req.sessionID = apis.encrypt(match[1], sessionKey);
						if (isEnvSession && !sessionStore[req.sessionID] && fs.existsSync(lastSessionFile)) {
							sessionStore[req.sessionID] = apis.deserialize(req, res, fs.readFileSync(lastSessionFile, 'utf8'));
						}
					} catch(e) {
						/* istanbul ignore next */
						console.error(e.stack);
					}
				}
			}
		}

		if (!req.sessionID) {
			var uid = crypto.randomBytes(32).toString('hex').slice(0, 32);
			res.cookie(sessionName, uid);
			req.sessionID = apis.encrypt(uid, sessionKey);
		}

		sessionStore[req.sessionID] = sessionStore[req.sessionID] || {
			time: null,
			data: {}
		};

		sessionStore[req.sessionID].time = Date.now();

		if (isEnvSession) {
			lastSessionId = req.sessionID;
			fs.writeFileSync(lastSessionFile, apis.serialize(req, res, sessionStore[req.sessionID]));
		}

		if (req.headers.cookie && req.headers.cookie.indexOf('x-cloud-ipaddress') === -1) {
			res.cookie('x-cloud-ipaddress', ipaddress);
		}

		if ((match = ipRegExp.exec(req.headers.cookie)) && match.length > 1 && match[1] !== ipaddress) {
			res.cookie('x-cloud-ipaddress', ipaddress);
			apis.getCookie(req, match[1], next);
		} else {
			req.session = sessionStore[req.sessionID].data;
			next();
		}
	});

	//clean session storage on local machine 
	if (expInterval !== -1) {
		setInterval(apis.cleanAll, expInterval * 1000);
	}

	return apis;
};