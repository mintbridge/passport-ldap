# Passport-LDAP

[Passport](http://passportjs.org/) strategy for authenticating against an OpenLDAP
server.

This module lets you authenticate against an OpenLDAP server in your Node.js applications.
By plugging into Passport, LDAP authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-ldap

## Usage

#### Configure Strategy

The LDAP authentication strategy authenticates requests by delegating to the
given ldap server using the openldap protocol.

The strategy requires a `verify` callback which accepts a user `profile` entry
from the directory, and then calls the `done` callback supplying a `user`.

    passport.use(new LDAPStrategy({
        url: 'ldap://0.0.0.0:1389',
        base: 'o=example',
        search: {
          filter: '(&(l=Seattle)(email=*@foo.com))',
         }
      },
      function(profile, done) {
        return done(null, profile);
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'ldap'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/login',
      passport.authenticate('facebook'));

    app.post('/auth/ldap',
      passport.authenticate('ldap', {
        successRedirect: '/',
        failureRedirect: '/auth/login/'
      })
    );

#### Profile Fields

## Examples

For a complete, working example, refer to the [login example](https://github.com/mintbridge/passport-ldap/tree/master/examples/login).

## Tests

    $ npm install --dev
    $ make test

[![Build Status](https://secure.travis-ci.org/mintbridge/passport-ldap.png)](http://travis-ci.org/mintbridge/mintbridge/passport-ldap)

## Credits

  - [Paul Dixon](http://github.com/mintbridge)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2011-2013 Paul Dixon <[http://www.mintbridge.co.uk/](http://www.mintbridge.co.uk)>
