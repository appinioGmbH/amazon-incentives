const request = require('request');
const convert = require('xml-js');
const crypto = require('crypto-js');
const { nanoid } = require('nanoid');

// Amazon Incentives API credentials
const accessKey = process.env.ACCESS_KEY || 'YOUR_ACCESS_KEY';
const secretKey = process.env.SECRET_KEY || 'YOUR_SECRET_KEY';

// Sandbox: https://agcod-v2-eu-gamma.amazon.com
// Production: https://agcod-v2-gamma.amazon.com
const HOST_URL = 'https://agcod-v2-eu-gamma.amazon.com';

const REGION = 'eu-west-1';
const SERVICE_NAME = 'AGCODService';
const OPERATION_NAME = 'CreateGiftCard';

const getSignatureKey = (key, dateStamp, regionName, serviceName) => {
  const kDate = crypto.HmacSHA256(dateStamp, "AWS4" + key);
  const kRegion = crypto.HmacSHA256(regionName, kDate);
  const kService = crypto.HmacSHA256(serviceName, kRegion);
  const kSigning = crypto.HmacSHA256("aws4_request", kService);
  return kSigning;
}

/**
 * Returns payload in XML format.
 *
 * @param {number} value The value of the gift card to be issued in Euro.
 * @return {string} Payload in XML format.
 */
const getPayloadAsXml = (value) => {
  const basePayload = {
    "CreateGiftCardRequest": {
      "creationRequestId": 'Appin_' + nanoid(),
      "partnerId": "Appin",
      "value": {
        "currencyCode": "EUR",
        "amount": value,
      }
    }
  };
  let options = {compact: true, ignoreComment: true, spaces: 4};
  let payloadAsXml = convert.json2xml(basePayload, options);

  return payloadAsXml;
};

/**
 * Returns signed AWS request with Signature Version 4.
 *
 * @param {string} accessKey Amazon access key.
 * @param {string} secretKey Amazon secret key.
 * @param {string} regionName Amazon region name (i.e.: us-east-1, eu-west-1, ...).
 * @param {string} serviceName Amazon service name (i.e.: AGCODService, ...).
 * @param {string} operation Amazon operation name (i.e.: CreateGiftCard, CancelGiftCard, ...).
 * @param {string} payload Payload in XML format.
 * @return {object} Object with the following signed AWS attr: authorization, host and amzDate.
 */
const signRequest = (accessKey, secretKey, regionName, serviceName, operation, payload) => {
  const algorithm = 'AWS4-HMAC-SHA256';
  let amzDate = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
  const dateStamp = amzDate.substr(0, amzDate.indexOf('T'));
  const credentialScope = `${dateStamp}/${regionName}/${serviceName}/aws4_request`;
  const canonicalQuerystring = '';
  const host = HOST_URL.split('https://')[1];
  const canonicalHeaders = 'content-type:application/xml\nhost:' + host + '\nx-amz-date:' + amzDate + '\n';
  const signedHeaders = 'content-type;host;x-amz-date';
  const payloadHash = crypto.SHA256(payload);
  const canonicalRequest  = `POST\n/${operation}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${crypto.SHA256(canonicalRequest).toString()}`;

  console.log('dateStamp', dateStamp);
  const signingKey = getSignatureKey(secretKey, dateStamp, REGION, SERVICE_NAME);
  // const signingKey = crypto.HmacSHA256(`${amzDate}/${regionName}/${serviceName}/aws4_request`, crypto.HmacSHA256(`${dateStamp}/${regionName}/${serviceName}/aws4_request`, crypto.HmacSHA256(`${dateStamp}/${regionName}/${serviceName}/aws4_request`, crypto.HmacSHA256(`${dateStamp}/${regionName}/${serviceName}/aws4_request`, crypto.HmacSHA256(`${dateStamp}/${regionName}/${serviceName}/aws4_request`, secretKey, 'utf8'), 'utf8'), 'utf8'), 'utf8'), 'utf8');
  // console.log('signingKey', signingKey);
  const signature = crypto.HmacSHA256(stringToSign, signingKey, 'hex');
  authorization = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { authorization, host, amzDate };
};

/**
 * Returns response of gift card creation request.
 *
 * @param {string} payload Payload in XML format.
 * @param {object} signature Object with the following signed AWS attr: authorization and amzDate.
 * @return {object} Response of gift card creation request.
 */
const createGiftCard = (payload, signature) => {
  return new Promise((resolve, reject) => {
    request({
      method: 'POST',
      url: `${HOST_URL}/CreateGiftCard`,
			headers: {
        'content-type': 'application/xml',
        'host': signature.host,
        'authorization': signature.authorization,
        'x-amz-date': signature.amzDate,
      },
      body: payload,
    }, (err, response) => {
      if (err) {
        return reject(err)
      }
      
      if (response && response.statusCode === 200) {
        const jsonResult = JSON.parse(convert.xml2json(response.body, {}));
        return resolve(jsonResult);
      }
      return resolve(response);
    });
  });
};

(async () => {
  try {
    const payload = await getPayloadAsXml(10);
    const auth = await signRequest(accessKey, secretKey, REGION, SERVICE_NAME, OPERATION_NAME, payload);
    const result = await createGiftCard(payload, auth);

    // console.log('result', result);
    console.log('result', result);
  } catch (error) {
    console.log(error);
  }
})();