const https = require('https');
const http = require('http');
const config = require('./config');
const AWS = require('aws-sdk');

const HTTP_PORT = 80;
const HTTPS_PORT = 443;

const decodeJwt = (token) => new Promise((resolve, reject) => {
    const lambda = new AWS.Lambda({
        region: config.aws.region
    });

    const params = {
        FunctionName: config.aws.decodeLambdaName,
        Payload: JSON.stringify({
            token
        })
    };

    lambda.invoke(params, (err, data) => {
        if (data.Payload === 'false') {
            reject('invalid JWT');
        } else if (err) {
            reject(err);
        }

        const payload = JSON.parse(data.Payload);

        if (payload.errorType === 'JWTError') {
            reject('Invalid token');
        }

        resolve(payload);
    });
});

const verifyAuthToken = (req) => new Promise((resolve, reject) => {
    if (!req.headers['access-token']) {
        reject('Missing access-token header');
    }

    if (!req.headers['hg-username']) {
        reject('Missing username in header');
    }

    decodeJwt(req.headers['access-token']).then((data) => {
        if (data.username === req.headers['hg-username']) {
            console.log('verified');
            resolve();
        } else {
            reject('JWT username does not match provided username');
        }
    }).catch(err => {
            reject('Could not verify auth token');
    });
});

const server = http.createServer((req, res) => {
    if (req.method === 'GET') {
        if (req.url === '/verify') {
            verifyAuthToken(req).then(() => {
                res.writeHead(200, {
                    'Content-Type': 'text/plain'
                });

                res.end('want to check your existing cert');
            }).catch(err => {
                res.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                res.end('Could not validate auth header');
            });
        } else if (req.url === '/') {

            verifyAuthToken(req).then(() => {
                res.writeHead(200, {
                    'Content-Type': 'text/plain'
                });
                res.end('you want to get your cert');
            }).catch(err => {
                res.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                res.end('Could not validate auth header');
            });

        } else {
            res.writeHead(404, {
                'Content-Type': 'text/plain'
            });
            res.end(`URL ${req.url} not found`);
        }
    } else { 
        res.writeHead(405, {
            'Content-Type': 'text/plain'
        });
        res.end('Unsupported method');
    }

});

server.listen(80);

//http.createServer((req, res) => {
//    res.writeHead(301, {'Location': 'https://' + req.headers['host'] + req.url });
//    res.end();
//}).listen(HTTP_PORT);
