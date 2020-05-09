const express = require('express');
const bodyParser = require('body-parser');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const app = express();
const morgan = require('morgan'); // log every request. https://github.com/expressjs/morgan

app.use(cookieParser());
// morgan - predefined formats: combined, common, dev, short, tiny. eg. app.use(morgan('dev'));
app.use(morgan(':remote-addr [:date[clf]] :status ":method :url" :response-time ms - :res[content-length]'));
app.use(compression());

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false, limit: '50mb' }));
// parse application/json
app.use(bodyParser.json({ limit: '50mb' }));

app.use(express.static(__dirname + '/www'));

// CORS
app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'OPTIONS, HEAD, GET, POST, PUT, PATCH, DELETE');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    next();
});

// app.engine("ejs", engine);
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.get('/', function (req, res) {
    res.render(`index`, {
        title: 'SSO-Server | Home',
    });
});

app.get('/favicon.ico', function (req, res) {
    res.sendStatus(204);
});

app.get('/api/hi', function (req, res) {
    res.json({ hi: 'Hello World!', params: req.params, query: req.query, body: req.body });
});

const router = express.Router();
const controller = require('./controller');
router.route('/login').get(controller.login).post(controller.doLogin);

router.get('/verifytoken', controller.verifySsoToken);

router.get('/logout', controller.logout);

app.use('/a-sso', router);

app.use((req, res, next) => {
    // catch 404 and forward to error handler
    const err = new Error('Resource Not Found');
    err.status = 404;
    next(err);
});

app.use((err, req, res, next) => {
    console.error({
        message: err.message,
        error: err,
    });
    const statusCode = err.status || 500;
    let message = err.message || 'Internal Server Error';

    if (statusCode === 500) {
        message = 'Internal Server Error';
    }
    res.status(statusCode).json({ message });
});

module.exports = app;
