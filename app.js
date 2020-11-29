const https = require('https');
const http = require('http');
const config = require('./config');
const fs = require('fs');
const AWS = require('aws-sdk');

const HTTP_PORT = 80;
const HTTPS_PORT = 443;

const options = {
	key: fs.readFileSync(config.TLS_KEY_PATH),
	cert: fs.readFileSync(config.TLS_CERT_PATH)
}

const updateUserCert = (username, certArn) => new Promise((resolve, reject) => {
    const provider = new AWS.CognitoIdentityServiceProvider({region: config.aws.region});
    const params = {
        UserAttributes: [
            {
                Name: 'custom:certArn',
                Value: certArn
            }
        ],
        UserPoolId: config.aws.cognito.USER_POOL_ID,
        Username: username
    };
    
    provider.adminUpdateUserAttributes(params, (err, data) => {
        resolve();
    });
});

const generateCert2 = (username) => new Promise((resolve, reject) => {
    console.log("generating cert for " + username);

	const { spawn } = require('child_process');
	const cmd = 'certbot';
	const args = ['certonly', '--dry-run', '--manual', '--preferred-challenges=dns', '-d *.' + username + '.homegames.link', '--email=joseph@homegamesio'];

        const child = spawn(cmd, args);
	let lineIsChallenge = false;
		child.stdout.on('data', (chunk) => {
			console.log('chunk');
			console.log(chunk.toString());
			const usernameChallengeUrl = `_acme-challenge.${username}.homegames.link`;
			if (chunk.toString().indexOf('(Y)es/(N)o:') == 0) {
				child.stdin.write('y\n');
			} else if (chunk.toString().indexOf('(A)gree/(C)ancel:') == 0) {
				child.stdin.write('A\n');
			} else if (chunk.toString().indexOf(usernameChallengeUrl) >= 0) {
				const dnsRegEx = new RegExp('\n\n(.*)\n\n');

				const dnsMatch = chunk.toString().match(dnsRegEx);
				if (dnsMatch) {
					const dnsChallenge = dnsMatch[1];
					console.log('need to create a dns record at ' + usernameChallengeUrl + ' for ' + dnsChallenge);
					createDNSRecord(usernameChallengeUrl, dnsChallenge).then(() => {
						child.stdin.write('\n');
						deleteDNSRecord(usernameChallengeUrl, dnsChallenge).then(() => {
							console.log('deleted that!!!');
						});

					}).catch(err => {
						if (err.toString().indexOf('but it already exists') >= 0) {
						    getDNSRecord(usernameChallengeUrl).then((value) => {
    						        deleteDNSRecord(usernameChallengeUrl, value).then(() => {
						            console.log("DELETED THAT COOL");	
						        });
						    });
						}
					});
				}
			}
		});
		child.stderr.on('data', (chunk) => {
			console.log('error!!!');
			console.log(chunk.toString());
		});

		child.on('error', (err) => {
			console.log('error');
			console.log(err);
			console.log(err.toString());
		});

		child.on('exit', (code) => {
			console.log('exited with code ' + code);
		});
});

const deleteDNSRecord = (name, value) => new Promise((resolve, reject) => {
    const deleteDnsParams = {
        ChangeBatch: {
            Changes: [
                {
                    Action: 'DELETE',
                    ResourceRecordSet: {
                        Name: name,//dnsChallengeRecord.Name,
                        Type: 'TXT',
                        TTL: 300,
                        ResourceRecords: [
                            {
                                Value: value,//dnsChallengeRecord.Value
                            }
                        ]
//                        TTL: 300,
//                        Type: dnsChallengeRecord.Type
                    }
                }
            ]
        },
        HostedZoneId: config.aws.route53.hostedZoneId
    };
    
	console.log('deleting');
        const route53 = new AWS.Route53();
    route53.changeResourceRecordSets(deleteDnsParams, (err, data) => {
	    console.log("DADASDAS");
	    console.log(err);
	    console.log(data);

        const deleteParams = {
            Id: data.ChangeInfo.Id
        };

	    console.log('waiting for deletion');
        route53.waitFor('resourceRecordSetsChanged', deleteParams, (err, data) => {
		console.log('sdfsdf');
		console.log(err);
		console.log(data);
            if (data.ChangeInfo.Status === 'INSYNC') {
                resolve();
            }
        });

    });

});

const getDNSRecord = (url) => new Promise((resolve, reject) => {
    const params = {
        HostedZoneId: config.aws.route53.hostedZoneId,
	StartRecordName: url,
	StartRecordType: 'TXT'
    };

    const route53 = new AWS.Route53();
    route53.listResourceRecordSets(params, (err, data) => {
	    for (const i in data.ResourceRecordSets) {
		    const entry = data.ResourceRecordSets[i];
		    if (entry.Name === url + '.') {
      			    resolve(entry.ResourceRecords[0].Value);
		    }
	    }
	reject();
    });

});

const createDNSRecord = (url, value) => new Promise((resolve, reject) => {
        const dnsParams = {
            ChangeBatch: {
                Changes: [
                    {
                        Action: 'CREATE',
                        ResourceRecordSet: {
                            Name: url,
                            ResourceRecords: [
                                {
                                    Value: '"' + value + '"'
                                }
                            ],
                            TTL: 300,
                            Type: 'TXT'
                        }
                    }
                ]
            },
            HostedZoneId: config.aws.route53.hostedZoneId
        };

        const route53 = new AWS.Route53();
        route53.changeResourceRecordSets(dnsParams, (err, data) => {
		if (err) {
		    reject(err);
		} else {
	            const params = {
                        Id: data.ChangeInfo.Id
                    };

	            console.log('waiting for creation');

                    route53.waitFor('resourceRecordSetsChanged', params, (err, data) => {
                        if (data.ChangeInfo.Status === 'INSYNC') {
			    resolve();
                        }
                    });
		}
        });
 
});

const getCertArn = (accessToken) => new Promise((resolve, reject) => {

    const params = {
        AccessToken: accessToken
    };

    const provider = new AWS.CognitoIdentityServiceProvider({region: config.aws.region});

    decodeJwt(accessToken).then(decoded => {
        provider.adminGetUser({
            Username: decoded.username,
            UserPoolId: config.aws.cognito.USER_POOL_ID
        }, (err, data) => {

            const certArn = data.UserAttributes.find(thing => thing.Name === 'custom:certArn');
            if (certArn) {
                resolve(certArn.Value);
            } else if (err) {
                reject(err); 
            } else {
                reject({type: 'NOT_FOUND'});
            }
        });
    });

});

const generateCert = (username) => new Promise((resolve, reject) => {
    const params = {
        DomainName: '*.' + username + '.homegames.link',
//        IdempotencyToken: 'abcd123',
        ValidationMethod: 'DNS'
    };

    const acm = new AWS.ACM({region: config.aws.region});

    acm.requestCertificate(params, (err, data) => {
        resolve(data);
    });
});

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
            resolve();
        } else {
            reject('JWT username does not match provided username');
        }
    }).catch(err => {
            reject('Could not verify auth token');
    });
});

const server = https.createServer(options, (req, res) => {
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

                const authToken = req.headers['access-token'];
                const username = req.headers['hg-username'];
                
                getCertArn(authToken).then((certArn) => {
                    const params = {
                        CertificateArn: certArn
                    };

                    const acm = new AWS.ACM({region: config.aws.region});
                    acm.getCertificate(params, (err, data) => {
                        if (err) {
                            res.writeHead(500);
                            res.end('error getting cert');
                        } else {
                            console.log("DATA");
                            console.log(data);
                            const privKey = data.Certificate;
                            const chain = data.CertificateChain; 
                            
                            const Archiver = require('archiver');
                            
                            res.writeHead(200, {
                                'Content-Type': 'application/zip',
                                'Content-Disposition': 'attachment; filename=certs.zip'
                            });

                            const zip = Archiver('zip');

                            zip.pipe(res);

                            zip.append(privKey, { name: 'certs/privkey.pem' })
                                .append(chain, { name: 'certs/fullchain.pem' })
                                .finalize();
                        }
                    });
                }).catch(err => {
                    if (err.type && err.type === 'NOT_FOUND') {
                        generateCert(username).then(certData => {
                            setTimeout(() => {
                                createRecords(certData.CertificateArn).then(() => {
                                    updateUserCert(username, certData.CertificateArn).then(() => {
                                        res.writeHead(200, {
                                            'Content-Type': 'text/plain'
                                        });
                                        res.end('you want to get your cert');
                                        const params = {
                                            CertificateArn: certArn
                                        };

                                        const acm = new AWS.ACM({region: config.aws.region});
                                        acm.getCertificate(params, (err, data) => {
                                            if (err) {
                                                res.writeHead(500);
                                                res.end('error getting cert');
                                            } else {
                                                const privKey = data.Certificate;
                                                const chain = data.CertificateChain; 
                                            }

                                        });
                                    });
                                });
                            }, 5000);
                        });
                    }
                });
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

server.listen(HTTPS_PORT);

http.createServer((req, res) => {
    res.writeHead(301, {'Location': 'https://' + req.headers['host'] + req.url });
    res.end();
}).listen(HTTP_PORT);

