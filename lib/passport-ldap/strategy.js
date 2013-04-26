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
 * Command line LDAP bind and search examples:
 * - Windows with Active Directory: ldapsearch -H ldap://192.168.1.17:389 -D XXX -w YYY -b dc=example,dc=local objectclass=*
 * - Linux/Sun Solaris with OpenLDAP: ldapsearch -H ldap://192.168.1.16:389 -D cn=XXX,dc=example,dc=local -w YYY -b dc=example,dc=local objectclass=*
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var self = this;

  if (!req.body.user || !req.body.pwd) {
    return self.fail(401);
  }

  var user = req.body.user;
  if (self._options.authMode === 1) {
    user = self._options.uidTag + '=' + req.body.user + ',' + self._options.base;
  }
  self.client.bind(user, req.body.pwd, function(err) {
    if (err) {
      if (self._options.debug) console.log('(EE) [ldapjs] LDAP error:', err.stack);
      return self.fail(403);
    }
    
    if (self._options.authOnly) {
      if (self._options.debug) console.log('(II) [ldapjs] auth success:', req.body.user);
      self.success({uid: req.body.user});
    } else {
      var dn = (self._options.authMode === 1 ? user : self._options.base);
      self._options.search.filter = self._options.search.filter.replace(/\$uid\$/, req.body.user);
      self.client.search(dn, self._options.search, function(err, res) {
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

