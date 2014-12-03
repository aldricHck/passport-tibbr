/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function(json) {
    if ('string' == typeof json) {
        json = JSON.parse(json);
    }

    var profile = {};
    profile.id = json.id;
    profile.username = json.login;
    profile.displayName = json.login;
    profile.name = { familyName: json.last_name,
        givenName: json.first_name };
    profile.email = json.email;

    return profile;
};