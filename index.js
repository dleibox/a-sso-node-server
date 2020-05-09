const app = require('./app');
const port = process.env.PORT || 8888;

app.listen(port, () => {
    console.info(`sso-server listening on port ${port}`);
});