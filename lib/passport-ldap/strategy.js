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
 *        server: {
 *          url: 'ldap://0.0.0.0:1389'
 *        },
 *        base: 'cn=users,dc=example,dc=local',
 *        search: {
 *          filter: '(&(l=Seattle)(email=*@foo.com))',
 *        }
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
      usernameField: 'user',
      passwordField: 'pwd',
      base: '',
      search: {
        filter: ''
      },
      authOnly: false,
      authMode: 1,        // 0 win, 1 Unix (linux, Solaris, ...)
      uidTag: 'uid',       // Linux OpenLDAP 'uid', Sun Solaris 'cn'
      debug: false
    };
  }
  if (!verify) throw new Error('LDAP authentication strategy requires a verify function');

  passport.Strategy.call(this);

  this.name = 'ldap';
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
 * Command line LDAP bind and search examples:
 * - Windows with Active Directory: ldapsearch -H ldap://192.168.1.17:389 -D XXX -w YYY -b dc=example,dc=local objectclass=*
 * - Linux/Sun Solaris with OpenLDAP: ldapsearch -H ldap://192.168.1.16:389 -D cn=XXX,dc=example,dc=local -w YYY -b dc=example,dc=local objectclass=*
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var self = this;
  // Create the client on every auth attempt the LDAP server can close the connection
  var Client = ldap.createClient(self._options.server);

  if (!req.body || !req.body[self._options.usernameField] || !req.body[self._options.passwordField]) {
    return self.fail(401);
  }

  var username = req.body[self._options.usernameField];

  if (self._options.authMode === 1) {
    var base = self._options.base;
    if(typeof base !== 'string'){
      base = base.join(',');
    }
    username = self._options.uidTag + '=' + username + ',' + base;
  }

  Client.bind(username, req.body[self._options.passwordField], function (err) {
    if (err) {
      if (self._options.debug) console.log('(EE) [ldapjs] LDAP error:', err.stack);
      return self.fail(403);
    }

    if (self._options.authOnly) {
      if (self._options.debug) console.log('(II) [ldapjs] auth success:', username);
      self.success({
        uid: username
      });
    } else {
      var dn = username;
      if (self._options.authMode !== 1) {
        // Add the dc from the username if not already in the configuration
        if(typeof self._options.base !== 'string'){
          var nameSplit = username.split('\\');
          var name = nameSplit[1];
          var dc = 'dc=' + nameSplit[0].toLowerCase();
  
          dn = self._options.base.slice();
          if (self._options.base.indexOf(dc) === -1) {
            dn.splice(0, 0, dc);
          }
          dn = dn.join(',');
        } else {
          dn = self._options.base;
        }
      }

      // Create copy of the search object so we don't overwrite it
      var search = Object.create(self._options.search);

      // Replace placeholder name
      search.filter = search.filter.replace(/\$uid\$/, name);
      Client.search(dn, search, function (err, res) {
        if (err) {
          if (self._options.debug) console.log('(EE) [ldapjs] LDAP error:', err.stack);
          return self.fail(403);
        }
    
        res.on('searchEntry', function(entry) {
          var profile = entry.object;

          self._verify(profile, function(err, user) {
            if (err) {
              if (self._options.debug) console.log('(EE) [ldapjs] LDAP error:', err.stack);
              return self.error(err);
            }
            if (!user) {
              if (self._options.debug) console.log('(EE) [ldapjs] LDAP user error:', self._challenge());
              return self.fail(self._challenge());
            }
            if (self._options.debug) console.log('(II) [ldapjs] auth success:', user);
            self.success(user);
          });
        });

        res.on('error', function(err) {
          if (self._options.debug) console.log('(EE) [ldapjs] Network error:', err.stack);
          self.error(err);
        });

        res.on('end', function(result) {
          if (result.status !== 0) {
            if (self._options.debug) console.log('(EE) [ldapjs] Result not OK:', result);
            self.fail(result.status);
          }
        });
      });
    }

  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
