const https = require('https');
const http = require('http');
const config = require('./config');
const fs = require('fs');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const { spawn } = require('child_process');
const zlib = require('zlib');

const HTTP_PORT = 80;
const HTTPS_PORT = 443;

const options = {
	key: fs.readFileSync(config.TLS_KEY_PATH),
	cert: fs.readFileSync(config.TLS_CERT_PATH)
}

const getUserHash = (username) => {
	return crypto.createHash('md5').update(username).digest('hex');
};

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

const generateCert = (username) => new Promise((resolve, reject) => {
    console.log("generating cert for " + username);

    const userHash = getUserHash(username);

    const cmd = 'certbot';

    const baseArgs = ['certonly'];

    if (config.ENVIRONMENT !== 'production') {
	baseArgs.push('--dry-run');
    }

    const additionalArgs = ['--manual', '--preferred-challenges=dns', '-d *.' + userHash + '.homegames.link', '--email=robot@homegamesio'];

    const args = [baseArgs, additionalArgs].flat();

    const child = spawn(cmd, args);
    child.stdout.on('data', (chunk) => {
	    console.log(chunk.toString());
     const usernameChallengeUrl = `_acme-challenge.${userHash}.homegames.link`;
     if (chunk.toString().indexOf('(Y)es/(N)o:') == 0) {
        child.stdin.write('y\n');
    } else if (chunk.toString().indexOf('(A)gree/(C)ancel:') == 0) {
        child.stdin.write('A\n');
    } else if (chunk.toString().indexOf(' - Congratulations! Your certificate and chain have been saved at:') >= 0) {
				console.log("got the path somewhere in here!");
	console.log(chunk.toString());
	const outputPathRegEx = new RegExp('Your key file has been saved at:\n(.*)\n   ');
	
	const outputPathMatch = chunk.toString().match(outputPathRegEx);
	
	if (outputPathMatch) { 
	    const outputPath = outputPathMatch[1].trim().split('/').filter(e => !e.endsWith('.pem')).join('/');;
	    resolve(outputPath);
	}

    } else if (chunk.toString().indexOf(usernameChallengeUrl) >= 0) {
        const dnsRegEx = new RegExp('\n\n(.*)\n\n');

        const dnsMatch = chunk.toString().match(dnsRegEx);
        if (dnsMatch) {
           const dnsChallenge = dnsMatch[1];
	   console.log('creating new DNS record for user.')
           createDNSRecord(usernameChallengeUrl, dnsChallenge).then(() => {
              child.stdin.write('\n');
              console.log('created. now deleting');
              deleteDNSRecord(usernameChallengeUrl).then(() => {
		  console.log('deleted record!');
              });

          }).catch(err => {
              if (err.toString().indexOf('but it already exists') >= 0) {
		  console.log('already has a dns record. deleting it.');
                  deleteDNSRecord(usernameChallengeUrl).then(() => {
	              console.log('deleted that. now need to create one');
           	      createDNSRecord(usernameChallengeUrl, dnsChallenge).then(() => {
                          child.stdin.write('\n');
                          console.log('created2. now deleting');
                          deleteDNSRecord(usernameChallengeUrl).then(() => {
             		      console.log('deleted2 record!');
				  resolve('/would/be/path');
                          });
                      });
                  });
              }
          });
      }
  }
});
    child.stderr.on('data', (_chunk) => {
	    const chunk = _chunk.toString();
			console.log('error!!!');
			console.log(_chunk.toString());
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

const deleteDNSRecord = (name) => new Promise((resolve, reject) => {
   
	getDNSRecord(name).then((value) => {
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

const route53 = new AWS.Route53();
route53.changeResourceRecordSets(deleteDnsParams, (err, data) => {
    const deleteParams = {
        Id: data.ChangeInfo.Id
    };

    route53.waitFor('resourceRecordSetsChanged', deleteParams, (err, data) => {
        if (data.ChangeInfo.Status === 'INSYNC') {
            resolve();
        }
    });

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
	    console.log(err);
	    console.log(data);
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

const getCert = (username) => new Promise((resolve, reject) => {
    	const userHash = getUserHash(username);
	console.log('getting ' + userHash);

	const s3 = new AWS.S3();
	const params = {
		Bucket: config.aws.s3.certBucket,
		Key: `${config.aws.s3.certPrefix}${userHash}/cert-bundle.zip`
	};

	s3.getObject(params, (err, data) => {
		if (err) {
			reject();
		} else {
			resolve(data.Body);
		}
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
        } else if (req.url === '/get-certs') {
		console.log('sdfsdf');
            verifyAuthToken(req).then(() => {

                const authToken = req.headers['access-token'];
                const username = req.headers['hg-username'];

	        getCert(username).then((data) => {
                            res.writeHead(200, {
                                'Content-Type': 'application/zip',
                                'Content-Disposition': 'attachment; filename=cert-bundle.zip'
                            });
		

			console.log('plau');
			res.end(data);

		}).catch((err) => {
		    console.log('need to create cert for ' + username);	
		    
		    generateCert(username).then(certPath => {
			console.log('created cert! at ' + certPath);
			
			storeCert(username, certPath).then((certData) => {
				console.log("STORED CERTS AT THIS HOLE SHNIT");
				console.log(certData);
	        getCert(username).then((data) => {
                            res.writeHead(200, {
                                'Content-Type': 'application/zip',
                                'Content-Disposition': 'attachment; filename=cert-bundle.zip'
                            });
		

			console.log('plau2');
			res.end(data);

		});
			});

		    });
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

const storeCert = (username, certPath) => new Promise((resolve, reject) => {
	console.log("need to store cert for user " + username);
    	const userHash = getUserHash(username);

	const archiver = require('archiver');
	const zipPath = `${config.TMP_DATA_DIR}/${userHash}_certs.gz`;
	const outStream = fs.createWriteStream(zipPath);

	console.log('writing to ' + zipPath);
	outStream.on('close', () => {
		console.log('stored! now i can upload to s3');
		
		fs.readFile(zipPath, (err, data) => {
                
			console.log('reading fileeee');
		const s3 = new AWS.S3();
		const certParams = {
			Body: data,
			Bucket: 'homegames-link',
			Key: `${config.aws.s3.certPrefix}${userHash}/cert-bundle.zip`
		};

			s3.putObject(certParams, (err, _data) => {
				console.log("okay");
				console.log(err);
				console.log(data);
				if (!err) {
					resolve(_data)
				}
			});
		});
	});

	const archive = archiver('zip');
	archive.pipe(outStream);
	console.log('sdfsdgfa');
	archive.directory(certPath, false);
	archive.finalize();
});
