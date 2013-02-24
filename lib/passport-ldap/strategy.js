/**
 * Module dependencies.
 */
var util = require('util');
var ldap = require('ldapjs');
var passport = require('passport');

/**
 * `Strategy` constructor.
 *
 * An LDAP authentication strategy authenticates requests by delegating to the
 * given ldap server using the openldap protocol.
 *
 * Applications must supply a `verify` callback which accepts a user `profile` entry
 * from the directory, and then calls the `done` callback supplying a `user`, which
 * should be set to `false` if the credentials are not valid.  If an exception occured,
 * `err` should be set.
 *
 * Options:
 *   - `server`  ldap server connection options - http://ldapjs.org/client.html#create-a-client
 *   - `base`    the base DN to search against
 *   - `search`  an object of containing search options - http://ldapjs.org/client.html#search
 *
 * Examples:
 *
 *     passport.use(new LDAPStrategy({
 *        url: 'ldap://0.0.0.0:1389',
 *        base: 'o=example',
 *        search: {
 *          filter: '(&(l=Seattle)(email=*@foo.com))',
*         }
 *      },
 *      function(profile, done) {
 *        return done(null, profile);
 *      }
 *    ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {
      server: {
        url : ''
      },
      base: '',
      search: {
        filter: ''
      }
    };
  }
  if (!verify) throw new Error('LDAP authentication strategy requires a verify function');

  passport.Strategy.call(this);

  this.name = 'ldap';
  this.client = ldap.createClient(options.server);
  this._verify = verify;
  this._options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request by binding to LDAP server, and then searching for the user entry.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var self = this;

  if (!req.body.username || !req.body.password) {
    return self.fail(401);
  }

  self.client.bind(req.body.username, req.body.password, function(err) {
    if (err) {
      return self.fail(403);
    }

    self.client.search(self._options.base, self._options.search, function(err, res) {
      if (err) {
        return self.fail(403);
      }

      res.on('searchEntry', function(entry) {
        var profile = JSON.stringify(entry.object);

        self._verify(profile, function(err, user) {
          if (err) {
            return self.error(err);
          }
          if (!user) {
            return self.fail(self._challenge());
          }
          self.success(user);
        });
      });
    });
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
