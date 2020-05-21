const { uuid } = require('uuidv4');
const Hashids = require('hashids/cjs');
// const URL = require('url').URL;
const hashids = new Hashids();

// app token to validate the request is coming from the authenticated server only.
const serverAuthTokenDB = {
    a_sso_server_auth_token: '8888',
};

const alloweOrigin = {
    localhost: true,
    'sso.localhost': true,
    'consumer.dlei.ca': true,
    'sso.dlei.ca': false,
};

// Note: express http converts all headers to lower case.
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

const deHyphenatedUUID = () => uuid().replace(/-/gi, '');
const encodedId = () => hashids.encodeHex(deHyphenatedUUID());

// A temporary cahce to store all the application that has login using the current session.
// It can be useful for variuos audit purpose
const sessionUser = {};
const sessionApp = {};

const userDB = {
    'dleibox@gmail.com': {
        password: 'test',
        userId: encodedId(), // incase you dont want to share the user-email.
        appPolicy: {
            sso_consumer: { role: 'admin', shareEmail: true },
            simple_sso_consumer: { role: 'user', shareEmail: false },
        },
    },
};

// these token are for the validation purpose
const intrmTokenCache = {};

const fillIntrmTokenCache = (origin, id, intrmToken) => {
    intrmTokenCache[intrmToken] = [id, origin];
};
const storeApplicationInCache = (origin, id, intrmToken) => {
    if (sessionApp[id] == null) {
        sessionApp[id] = {
            [origin]: true,
        };
    } else {
        sessionApp[id][origin] = true;
    }
    fillIntrmTokenCache(origin, id, intrmToken);
};

const generatePayload = (ssoKey) => {
    const globalSessionToken = intrmTokenCache[ssoKey][0];
    // const appName = intrmTokenCache[ssoKey][1];
    const userEmail = sessionUser[globalSessionToken];
    const user = userDB[userEmail];
    // const appPolicy = user.appPolicy[appName];
    const email = userEmail; // appPolicy.shareEmail === true ? userEmail : undefined;
    const payload = {
        // ...{ ...appPolicy },
        ...{
            email,
            // shareEmail: undefined,
            uid: user.userId,
            // global SessionID for the logout functionality.
            globalSessionID: globalSessionToken,
        },
    };
    return payload;
};

const fs = require('fs');
const path = require('path');
const ISSUER = 'a-sso';
const jwt = require('jsonwebtoken');
const privateCert = fs.readFileSync(path.resolve(__dirname, '../jwtPrivate.key'));
const genJwtToken = async (payload) => {
    return new Promise((resolve, reject) => {
        // some of the libraries and libraries written in other language,
        // expect base64 encoded secrets, so sign using the base64 to make
        // jwt useable across all platform and langauage.
        jwt.sign(
            { ...payload },
            privateCert,
            {
                algorithm: 'RS256',
                expiresIn: '1h',
                issuer: ISSUER,
            },
            (err, token) => {
                if (err) return reject(err);
                return resolve(token);
            }
        );
    });
};

function parseAuthHeader(hdrValue) {
    if (typeof hdrValue !== 'string') {
        return null;
    }
    const matches = hdrValue.match(/(\S+)\s+(\S+)/);
    return matches && { scheme: matches[1], value: matches[2] };
}

const verifySsoKey = async (req, res, next) => {
    const auth = req.headers[AUTH_HEADER];
    let serverAuthToken = null;
    if (auth) {
        const authParams = parseAuthHeader(auth);
        if (authParams && BEARER_AUTH_SCHEME === authParams.scheme.toLowerCase()) {
            serverAuthToken = authParams.value;

            console.log('---server_auth_token---:', serverAuthToken);
            const { ssoKey } = req.query;
            // if the application token is not present or ssoKey request is invalid
            // if the ssoKey is not present in the cache some is
            // smart.
            if (!serverAuthToken || !ssoKey || !intrmTokenCache[ssoKey]) {
                return res.status(400).json({ message: 'badRequest' });
            }
            // if the serverAuthToken is present and check if it's valid for the application
            const [globalSessionToken, appName] = intrmTokenCache[ssoKey];

            // If the serverAuthToken is not equal to token given during the sso app registraion or later stage than invalid
            if (serverAuthToken !== serverAuthTokenDB['a_sso_server_auth_token'] || sessionApp[globalSessionToken][appName] !== true) {
                return res.status(403).json({ message: 'Unauthorized' });
            }

            // checking if the token passed has been generated
            const payload = generatePayload(ssoKey);
            const token = await genJwtToken(payload);
            console.log('---app_token---:', token);
            // delete the itremCache key for no futher use,
            // delete intrmTokenCache[ssoKey];
            return res.status(200).json({ token });
        }
    }
    res.status(400).json({ message: 'SSO Token invalid' });
};

const doLogin = (req, res, next) => {
    // do the validation with email and password
    // but the goal is not to do the same in this right now,
    // like checking with Datebase and all, we are skiping these section
    const { email, password } = req.body;
    if (!(userDB[email] && password === userDB[email].password)) {
        return res.status(404).json({ message: 'Invalid email and password' });
    }
    // else redirect
    const { appURL } = req.query;
    const id = encodedId();
    //// req.session.user = id;
    sessionUser[id] = email;
    res.cookie('sso_token', id, { maxAge: 2 * 60 * 1000 }); //, { expires: ... }); // The max-age directive takes priority over Expires
    if (appURL == null) {
        return res.redirect('/');
    }
    const url = new URL(appURL);
    const intrmid = encodedId();
    storeApplicationInCache(url.origin, id, intrmid);
    res.redirect(302, `${appURL}?ssoKey=${intrmid}`);
};

const login = (req, res, next) => {
    // The req.query will have the redirect url where we need to redirect after successful
    // login and with sso token.
    // This can also be used to verify the origin from where the request has came in
    // for the redirection
    const { appURL } = req.query;
    // direct access will give the error inside new URL.
    if (appURL != null) {
        const url = new URL(appURL);
        if (alloweOrigin[url.hostname] !== true) {
            return res.status(400).json({ message: 'Your are not allowed to access the sso-server' });
        }
    }
    if (req.cookies.sso_token != null && appURL == null) {
        return res.redirect('/');
    }
    // if global session already has the user directly redirect with the token
    if (req.cookies.sso_token != null && appURL != null) {
        console.log('---', req.cookies.sso_token, intrmTokenCache);
        const intrmid = Object.keys(intrmTokenCache).find((_) => intrmTokenCache[_][0] === req.cookies.sso_token);
        if (intrmid) {
            return res.redirect(302, `${appURL}?ssoKey=${intrmid}`);
        }
    }
    return res.render('login', {
        title: 'SSO-Server | Login',
    });
};

const logout = (req, res, next) => {
    res.clearCookie('sso_token');
    res.redirect('/');
};

module.exports = Object.assign({}, { doLogin, login, verifySsoKey, logout });
