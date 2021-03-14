const http = require('http');
const fs = require('fs');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const { spawn } = require('child_process');
const zlib = require('zlib');
const { verifyAccessToken } = require('homegames-common');

const HTTP_PORT = 80;

const getUserHash = (username) => {
	return crypto.createHash('md5').update(username).digest('hex');
};

const updateUserCert = (username, certArn) => new Promise((resolve, reject) => {
    const provider = new AWS.CognitoIdentityServiceProvider({region: process.env.AWS_REGION});
    const params = {
        UserAttributes: [
        {
            Name: 'custom:certArn',
            Value: certArn
        }
        ],
        UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
        Username: username
    };
    
    provider.adminUpdateUserAttributes(params, (err, data) => {
        resolve();
    });
});

const generateCert = (username) => new Promise((resolve, reject) => {
    const userHash = getUserHash(username);

    const cmd = 'certbot';

    const baseArgs = ['certonly'];

    if (process.env.ENVIRONMENT !== 'production') {
	baseArgs.push('--dry-run');
    }

    const additionalArgs = ['--manual', '--preferred-challenges=dns', '-d *.' + userHash + '.homegames.link', '--email=robot@homegamesio'];

    const args = [baseArgs, additionalArgs].flat();

    const child = spawn(cmd, args);
    child.stdout.on('data', (chunk) => {
     const usernameChallengeUrl = `_acme-challenge.${userHash}.homegames.link`;
     if (chunk.toString().indexOf('(Y)es/(N)o:') == 0) {
        child.stdin.write('y\n');
    } else if (chunk.toString().indexOf('(A)gree/(C)ancel:') == 0) {
        child.stdin.write('A\n');
    } else if (chunk.toString().indexOf(' - Congratulations! Your certificate and chain have been saved at:') >= 0) {
	const outputPathRegEx = new RegExp('Your key file has been saved at:\n(.*)\n   ');
	
	const outputPathMatch = chunk.toString().match(outputPathRegEx);
	
	if (outputPathMatch) { 
	    const outputPath = outputPathMatch[1].trim().split('/').filter(e => !e.endsWith('.pem')).join('/');;
	    resolve(outputPath);
	}

    } else if (chunk.toString().indexOf('You have an existing certificate that has exactly the same domains') >= 0) {
        child.stdin.write('2\n');    
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
		});

    child.on('error', (err) => {
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
HostedZoneId: process.env.AWS_ROUTE_53_HOSTED_ZONE_ID
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
        HostedZoneId: process.env.AWS_ROUTE_53_HOSTED_ZONE_ID,
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
        HostedZoneId: process.env.AWS_ROUTE_53_HOSTED_ZONE_ID
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

    const provider = new AWS.CognitoIdentityServiceProvider({region: process.env.AWS_REGION});

    decodeJwt(accessToken).then(decoded => {
        provider.adminGetUser({
            Username: decoded.username,
            UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID
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
        region: process.env.AWS_REGION
    });

    const params = {
        FunctionName: process.env.AWS_DECODE_LAMBDA_NAME,
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

const getCert = (username) => new Promise((resolve, reject) => {
    	const userHash = getUserHash(username);

	const s3 = new AWS.S3();
	const params = {
		Bucket: process.env.AWS_S3_CERT_BUCKET,
		Key: `${process.env.AWS_S3_CERT_PREFIX}${userHash}/cert-bundle.zip`
	};

	s3.getObject(params, (err, data) => {
		if (err) {
			reject();
		} else {
			resolve(data.Body);
		}
	});
});

const getReqBody = (req, cb) => {
    let _body = '';
    req.on('data', chunk => {
        _body += chunk.toString();
    });

    req.on('end', () => {
        cb && cb(_body);
    });
};

const getCertDir = (username) => new Promise((resolve, reject) => {
	const userHash = getUserHash(username);
	fs.readFile(`/etc/letsencrypt/renewal/${userHash}.homegames.link.conf`, (err, data) => {
		const cmd = 'certbot';
		const args = ['certificates', '--cert-name', `${userHash}.homegames.link`];
		    const child = spawn(cmd, args);
    child.stdout.on('data', (chunk) => {
	const expirationRegex = new RegExp('Expiry Date: (.*)\n');
	    if (chunk.toString().match(expirationRegex)) {
		console.log("EXPIRATION DATA");
		    console.log(chunk.toString().match(expirationRegex)[1]);
	    }

    });
    child.stderr.on('data', (_chunk) => {
	    const chunk = _chunk.toString();
		});

    child.on('error', (err) => {
		});

		resolve();
	});
});

const server = http.createServer((req, res) => {
	if (req.method === 'POST') {
	    if (req.url === '/verify') {
                const username = req.headers['hg-username'];
		    const accessToken = req.headers['hg-access-token']
            verifyAccessToken(username, accessToken).then(() => {
		    getReqBody(req, (_reqData) => {
			    const reqData = JSON.parse(_reqData);
                res.writeHead(200, {
                    'Content-Type': 'application/json'
                });

	        	getCert(username).then((certData) => {
				const checksum = crypto.createHash('md5').update(certData).digest('hex');
		    const payload = {
                        //todo: maybe one day
			success: true //checksum === reqData.checksum 
		    };

				getCertDir(username).then(() => {
                res.end(JSON.stringify(payload));
				});

			}).catch(err => {
				res.writeHead(200, {
					'Content-Type': 'application/json'
				});
				res.end(JSON.stringify({
					message: 'No cert found',
					success: false
				}));
			});
		    });
            }).catch(err => {
                res.writeHead(400, {
                    'Content-Type': 'text/plain'
                });
                res.end('Could not validate auth header');
            });
	    }

	} else if (req.method === 'GET') {
        if (req.url === '/get-certs') {
            const accessToken = req.headers['hg-access-token'];
            const username = req.headers['hg-username'];

            verifyAccessToken(username, accessToken).then((data) => {

	        getCert(username).then((data) => {
                            res.writeHead(200, {
                                'Content-Type': 'application/zip',
                                'Content-Disposition': 'attachment; filename=cert-bundle.zip'
                            });
		

			res.end(data);

		}).catch((err) => {
		    
		    generateCert(username).then(certPath => {
			
			storeCert(username, certPath).then((certData) => {
	        getCert(username).then((data) => {
                            res.writeHead(200, {
                                'Content-Type': 'application/zip',
                                'Content-Disposition': 'attachment; filename=cert-bundle.zip'
                            });

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

        } else if (req.url === '/health') {
            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });
            res.end('ok');

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

server.listen(HTTP_PORT);

const storeCert = (username, certPath) => new Promise((resolve, reject) => {
    	const userHash = getUserHash(username);

	const archiver = require('archiver');
	const zipPath = `${process.env.TMP_DATA_DIR}/${userHash}_certs.gz`;
	const outStream = fs.createWriteStream(zipPath);

	outStream.on('close', () => {
		fs.readFile(zipPath, (err, data) => {
                
		const s3 = new AWS.S3();
		const certParams = {
			Body: data,
			Bucket: 'homegames-link',
			Key: `${process.env.AWS_S3_CERT_PREFIX}${userHash}/cert-bundle.zip`
		};

			s3.putObject(certParams, (err, _data) => {
				if (!err) {
					resolve(_data)
				}
			});
		});
	});

	const archive = archiver('zip');
	archive.pipe(outStream);
	archive.append(fs.createReadStream(certPath + '/fullchain.pem'), {name: 'fullchain.pem'});
	archive.append(fs.createReadStream(certPath + '/privkey.pem'), {name: 'privkey.pem'});
	archive.finalize();
});
