/** @module sessions
 * A module representing a user session
 */

module.exports = {
    create: create,
    destroy: destroy,
    loginRequired: loginRequired
};

var json = require('../../lib/form-json');
var encryption = require('../../lib/encryption');

/** @function create
 * Creates a new session
 */
function create(req, res, db) {
    json(req, res, function(req, res) {
        var username = req.body.username;
        var password = req.body.password; // password will be plaintext because it's being sent over SSL

        db.get(
            "SELECT * FROM users WHERE username=?",
            [username],
            function(err, user) {
                if (err) {
                    res.statusCode = 500;
                    res.end("Server error during authentication.");
                    return;
                }

                /* don't want to give away too much info on errors, since
                 * people can use informative authentication error messages
                 * to figure out usernames and ruin our lives
                 */
                if (!user) {
                    // username not in database
                    res.statusCode = 403; // authentication error
                    res.end("Incorrect username/password");
                    return;
                }

                var cryptedPassword = encryption.digest(password + user.salt);

                if (cryptedPassword != user.cryptedPassword) {
                    // invalid password/username combination
                    res.statusCode = 403; // v harsh
                    res.end("Incorrect username/password");
                    return;
                } else {
                    // Successful login!

                    /* store user.id in encrypted cookie so
                     *  (1) we can remember that we authenticated the user for this session, and
                     *  (2) randos can't easily fake a user's authentication cookie
                     */

                    // Store user.id in the cookie
                    var cookieData = JSON.stringify({userId: user.id});

                    // Encrypt cookie
                    var encrytedCookieData = encryption.encipher(cookieData);

                    res.setHeader(
                        "Set-Cookie",
                        ["session=" + encryptedCookieData]
                    );
                    res.statusCode = 200;
                    res.end("Successful login!");
                }
            }
        );
    });
}

function destroy(req, res) {
    // destroy the session cookie and load the main page
    // ('load main page' -> AJAX our way back to the main page)
    res.setHeader("Set-Cookie", [""]); // flushes the cookie
    res.statusCode = 200;
    res.end("Logged out successfully.");
}

function loginRequired(req, res, next) {
    // this is what's known as a 'middleware function'
    var session = req.headers.cookie.session;
    var sessionData = encryption.decipher(session);
    var sessionObj = JSON.parse(sessionData);

    if (sessionObj.userId) {
        req.currentUserId = sessionObj.userId;
        return next(req, res);
    } else {
        res.statusCode = 403;
        res.end("Authentication required.");
    }
}
