import config from './config.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import * as jose from 'jose';

let discoveryData;
const readFromDiscoveryEndpoint = async () => {
  return new Promise(async (resolve, reject) => {
    try {
      const issuer = config.ISSUER_URL;
      const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
      const response = await axios.get(discoveryUrl);
      discoveryData = response.data;

      resolve(discoveryData);
    } catch (error) {
      reject(error);
    }
  });
};

function getContentType(filePath) {
  const extension = filePath.split('.').pop(); // Get the file extension
  switch (extension) {
    case 'html':
      return 'text/html';
    case 'css':
      return 'text/css';
    case 'js':
      return 'application/javascript';
    case 'png':
      return 'image/png';
    case 'jpg':
      return 'image/jpeg';
    case 'jpeg':
      return 'image/jpeg';
    case 'gif':
      return 'image/gif';
    case 'json':
      return 'application/json';
    case 'txt':
      return 'text/plain';
    default:
      return 'application/octet-stream'; // For unknown file types
  }
}

function generateCodeVerifier() {
  const buffer = crypto.randomBytes(64);
  return buffer.toString('base64url');
}

function generateCodeChallenge(code_verifier) {
  const hash = crypto.createHash('sha256').update(code_verifier).digest();
  return hash.toString('base64url');
}

export const sessionInit = async (event, context, callback) => {
  const discoveryData = await readFromDiscoveryEndpoint();

  // Your sessionInit logic here
  const nonce = crypto.randomUUID();
  const state = crypto.randomBytes(16).toString('hex');
  const code_verifier = generateCodeVerifier();
  const code_challenge = generateCodeChallenge(code_verifier);

  const redirect_uri = config.REDIRECT_URI;

  const authorization_url = encodeURI(
    `${discoveryData.authorization_endpoint}?scope=${config.SCOPES}&response_type=code&redirect_uri=${redirect_uri}&code_challenge_method=S256&code_challenge=${code_challenge}&nonce=${nonce}&state=${state}&client_id=${config.CLIENT_ID}`
  );

  // Store these values in the session cookie (or session store if needed)
  const sessionId = crypto.randomBytes(16).toString('hex'); // Unique session ID

  // Set session data as cookie
  const cookieValue = JSON.stringify({ sessionId, nonce, state, code_verifier });

  // Set the cookie options (these can be adjusted based on security needs)
  const cookieOptions = {
    httpOnly: true, // Ensures the cookie is not accessible via JavaScript
    secure: true, // Only sends cookie over HTTPS
    maxAge: 60, // 60s
    path: '/',
  };

  // Convert cookie options to string
  const cookieOptionsString = Object.entries(cookieOptions)
    .map(([key, value]) => `${key}=${value}`)
    .join('; ');

  // Set the cookie header
  const cookieHeader = `session=${encodeURIComponent(cookieValue)}; ${cookieOptionsString}`;

  const response = {
    statusCode: 302,
    headers: {
      Location: authorization_url,
      'Set-Cookie': cookieHeader, // Set the cookie header
    },
  };

  console.log(response);

  callback(null, response);
};

export const callback = async (event) => {
  const queryParams = event.queryStringParameters;

  discoveryData = await readFromDiscoveryEndpoint();
  // Extract individual parameters
  const code = queryParams.code;
  const state = queryParams.state;
  const error = queryParams.error;

  // Handle the extracted parameters as needed
  if (error) {
    console.error(`Error received: ${error}`);
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Authentication failed' }),
    };
  }

  // Your logic to handle the code and state parameters

  //form JWT
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: config.CLIENT_ID,
    aud: discoveryData.issuer,
    iss: config.CLIENT_ID,
    iat: now,
    exp: now + 120, // 2 minutes expiration
    code: code,
  };

  const header = {
    alg: 'ES256',
    typ: 'JWT',
  };

  const privateKey = config.KEYS['PRIVATE_SIG_KEY']; // Ensure you have your private key in config
  const ecPrivateKey = await jose.importJWK(
    {
      kty: privateKey.kty,
      crv: privateKey.crv,
      x: privateKey.x,
      y: privateKey.y,
      d: privateKey.d,
    },
    'ES256'
  );

  const cookieHeader = event.headers.Cookie || event.headers.cookie;
  if (!cookieHeader) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'No cookies found' }),
    };
  }
  // Parse the session cookie value
  const sessionData = JSON.parse(decodeURIComponent(cookieHeader.split('session=')[1]));
  const code_verifier = sessionData.code_verifier;
  const token = jwt.sign(payload, ecPrivateKey, { algorithm: 'ES256', header: header });
  const body = {
    client_id: config.CLIENT_ID,
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: config.REDIRECT_URI,
    scope: 'openid',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: token,
    code_verifier: code_verifier,
  };

  let token_response;
  try {
    token_response = await axios.post(discoveryData.token_endpoint, body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=ISO-8859-1',
      },
    });
  } catch (error) {
    console.error('Error exchanging code for token:', error);
  }
  let userinfo_response;
  console.log(token_response.data);
  try {
    userinfo_response = await axios.get(discoveryData.userinfo_endpoint, {
      headers: {
        Authorization: `Bearer ${token_response.data.access_token}`,
      },
    });

    // Set the encrypted user info in the session cookie
    const sessionData = JSON.stringify({ data: userinfo_response.data });

    // Set the cookie options (these can be adjusted based on security needs)
    const cookieOptions = {
      httpOnly: true, // Allows the cookie to be accessible via JavaScript
      secure: true, // Only sends cookie over HTTPS
      maxAge: 3600, // 30s
      path: '/',
      sameSite: 'none',
    };

    // Convert cookie options to string
    const cookieOptionsString = Object.entries(cookieOptions)
      .map(([key, value]) => `${key}=${value}`)
      .join('; ');
    const sessionCookie = `data=${encodeURIComponent(sessionData)}; ${cookieOptionsString}`;
    console.log(sessionCookie);
    return {
      statusCode: 302,
      headers: {
        'Set-Cookie': sessionCookie,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
        Location: 'https://javierpng.github.io/sp-demo-jv',
      },
    };
  } catch (error) {
    console.error('Error exchanging for userinfo', error);
  }
};

export const getKey = async (event, context, callback) => {
  const publicSigKey = config.KEYS['PUBLIC_SIG_KEY'];
  const publicEncKey = config.KEYS['PUBLIC_ENC_KEY'];
  const object = { keys: [publicSigKey, publicEncKey] };
  const response = {
    statusCode: 200,
    body: JSON.stringify(object),
  };
  callback(null, response);
};

export const serve = async (event, context, callback) => {
  // Get the path parameter from the event
  const filePath = event.pathParameters.proxy || 'index.html'; // Default to 'index.html' if no path is provided
  console.log(filePath);
  try {
    // Fetch the file from the S3 bucket
    const data = await s3
      .getObject({
        Bucket: 'sp-demo-jv',
        Key: 'index.html',
      })
      .promise();

    console.log(data);

    // Determine the content type based on the file extension
    const contentType = getContentType(filePath);

    // Return the file content with the appropriate headers
    return {
      statusCode: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'max-age=3600', // Cache the file for 1 hour (adjust as needed)
      },
      body: data.Body.toString('utf-8'), // Convert the file data to string (text-based files like HTML, CSS, etc.)
    };
  } catch (error) {
    console.error('Error fetching the file:', error);

    // Return a 404 error if the file is not found
    return {
      statusCode: 404,
      body: 'File Not Found',
    };
  }
};

export const user = async (event, context, callback) => {
  try {
    const cookieHeader = event.headers.Cookie || event.headers.cookie;
    console.log(cookieHeader);
    if (!cookieHeader) {
      console.log('no cookie found');
      return {
        statusCode: 400,
      };
    }
    // Parse the session cookie value
    const sessionData = JSON.parse(decodeURIComponent(cookieHeader.split('data=')[1].split(';')[0]));
    if (!sessionData) {
      return {
        statusCode: 401,
      };
    } else {
      const enc_key = config.KEYS['PRIVATE_ENC_KEY'];
      const enc_private_key = await jose.importJWK(
        {
          kty: enc_key.kty,
          crv: enc_key.crv,
          x: enc_key.x,
          y: enc_key.y,
          d: enc_key.d,
        },
        'ECDH-ES+A256KW'
      );

      const { plaintext } = await jose.compactDecrypt(sessionData.data, enc_private_key);
      const decodedUserInfo = new TextDecoder().decode(plaintext);
      let jwtPayload = JSON.stringify(jwt.decode(decodedUserInfo));
      const response = {
        statusCode: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': true,
        },
        body: jwtPayload,
      };

      callback(null, response);
    }
  } catch (error) {
    console.log(error);
    return {
      statusCode: 403,
    };
  }
};
