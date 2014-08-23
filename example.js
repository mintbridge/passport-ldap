var express = require('express');
var session = require('express-session');
var LDAPStrategy = require('passport-ldap').Strategy;

// Windows LDAP
var ldapConfig = {
    server: {
        url: 'ldap://some.server.url.com:9999'
    },
    authMode: 0,
    debug: false,
    usernameField: 'username',
    passwordField: 'password',
    base: ['dc=ad','dc=sm','dc=else'],
    search: {
        filter: '(sAMAccountName=$uid$)',
        scope: 'sub',
        attributes: ['list','of','user','attributes','you','want','returned'],
        sizeLimit: 1
    },
    searchAttributes: ['displayName']
};

module.exports = function(app,passport){
  app.use(session({
      secret: 'anawesomesecret'
  }));

  passport.use(new LDAPStrategy(
      ldapConfig,
      function(profile, done) {
          return done(null, profile);
      }
  ));

  passport.serializeUser(function(user,done){
      done(null,user);
  });

  passport.deserializeUser(function(user,done){
      done(null,user);
  });

  app.use(passport.initialize());
  app.use(passport.session());
};
