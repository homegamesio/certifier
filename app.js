const https = require('https');
const http = require('http');

const HTTP_PORT = 80;
const HTTPS_PORT = 443;


const server = http.createServer((req, res) => {
    if (req.method === 'GET') {
        if (req.url === '/verify') {
            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });
            res.end('want to check your existing cert');
        } else if (req.url === '/') {
            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });
            res.end('you want to get your cert');
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
