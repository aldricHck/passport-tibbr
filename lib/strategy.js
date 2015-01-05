/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Facebook application's App ID
 *   - `clientSecret`  your Facebook application's App Secret
 *   - `callbackURL`   URL to which Facebook will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new FacebookStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/facebook/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'http://tibbr.hck-solutions.com/a/oauth/authorizations/authorize';
  options.tokenURL = options.tokenURL || 'http://tibbr.hck-solutions.com/oauth/a/authorizations/authorize';
  options.scopeSeparator = options.scopeSeparator || ',';
  this._userProfileURL = options.userProfileURL || 'http://tibbr.hck-solutions.com/a/users/find_by_auth_token.json';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'tibbr';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Windows Live.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `windowslive`
 *   - `id`               the user's Windows Live ID
 *   - `displayName`      the user's full name
 *
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;



  if (req.body && req.body.access_token) {

    var access_token = req.body.access_token;



    self._loadUserProfile(access_token, function(err, profile) {
      if (err) { return self.error(err); }

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }

      try {
        if (self._passReqToCallback) {

          self._verify(req, access_token, profile, verified);
        } else {

          self._verify(access_token, profile, verified);
        }
      } catch (ex) {
        return self.error(ex);
      }
    });


  } else {
    var params = {};

    this._oauth2._authorizeUrl = options.authorizationURL;
    this._oauth2._accessTokenUrl = options.tokenURL;
    this._oauth2.clientId = req.params.clientId;
    this._oauth2.clientSecret = req.params.clientSecret;
    this._userProfileURL = options.userProfileURL;
    params.client_secret = this._oauth2._clientSecret;
    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};


Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
        var json;
        if (err) {
            if (err.data) {
                try {
                    json = JSON.parse(err.data);
                } catch (_) {}
            }

            if (json && json.error) {
                return done(new LiveConnectAPIError(json.error.message, json.error.code));
            }
            return done(new InternalOAuthError('Failed to fetch user profile', err));
        }

        try {
            json = JSON.parse(body);
        } catch (ex) {
            return done(new Error('Failed to parse user profile'));
        }

        var profile = Profile.parse(json);
        profile.provider  = 'tibbr';
        profile._raw = body;
        profile._json = json;
        done(null, profile);
    });
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
