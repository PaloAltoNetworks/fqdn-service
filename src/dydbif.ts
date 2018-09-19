import * as aws from 'aws-sdk';
import * as utils from './utils';

const DBKEY = 'id';
const QS_KEY_PARAM = 'key';
export const STAGE_SECRET = 'secret';
export const STAGE_TABLE = 'dbtable';

let docuClient = new aws.DynamoDB.DocumentClient();
let serviceConfig: { [name: string]: Object } = {};

export interface addrValidUntil {
    [address: string]: number
}

export interface fqdnDbItem {
    [DBKEY]: string,
    ipv4: addrValidUntil,
    ipv6: addrValidUntil
}

function refreshConfigFromDatastore(table: string, configFile: string): Promise<Object> {
    return new Promise<Object>((resolve, reject) => docuClient.get({
        TableName: table,
        Key: {
            [DBKEY]: configFile
        }
    }, (err, data) => {
        if (err != null) {
            reject(err.message);
            return;
        }
        if (data == null) {
            reject('Empty configuration file');
            return;
        }
        let configBody = data.Item;
        if (typeof configBody != "object" || !('config' in configBody) || typeof configBody['config'] != "object") {
            reject('Invalid config in the dataStore');
        } else {
            serviceConfig[configFile] = configBody['config'] as Object;
            resolve(JSON.parse(JSON.stringify(serviceConfig[configFile])));
        }
    }));
}

function putNewConfig(table: string, configFile: string, configBody: Object): Promise<aws.DynamoDB.DocumentClient.PutItemOutput> {
    return new Promise<aws.DynamoDB.DocumentClient.PutItemOutput>((resolve, reject) => docuClient.put({
        TableName: table,
        Item: {
            [DBKEY]: configFile,
            config: configBody
        }
    }, (err, data) => {
        if (err != null) {
            reject(err.message);
        } else {
            serviceConfig[configFile] = configBody;
            resolve(configBody);
        }
    }))
}

export function getConfig(table: string, configFile: string): Promise<Object> {
    if (!(configFile in serviceConfig)) {
        return refreshConfigFromDatastore(table, configFile);
    }
    return Promise.resolve(JSON.parse(JSON.stringify(serviceConfig[configFile])));
}

export function safeGetById(table: string, id: string): Promise<fqdnDbItem> {
    return new Promise<fqdnDbItem>((resolve, reject) => docuClient.get({
        TableName: table,
        Key: {
            [DBKEY]: id
        }
    }, (err, data) => {
        if (err != null || data == null || !("Item" in data)) {
            resolve({ [DBKEY]: id, ipv4: {}, ipv6: {} });
        } else {
            resolve(data.Item as fqdnDbItem);
        }
    }))
}

export function putItem(table: string, item: fqdnDbItem): Promise<void> {
    return new Promise<void>((resolve, reject) => docuClient.put({
        TableName: table,
        Item: item
    }, (err, data) => {
        if (err != null) {
            reject(err.message);
        } else {
            resolve();
        }
    }));
}

export function configHandler(event: AWSLambda.APIGatewayProxyEvent): Promise<AWSLambda.APIGatewayProxyResult> {
    let qs = event.queryStringParameters;
    let secret = event.stageVariables ? event.stageVariables[STAGE_SECRET] : event.requestContext.requestId;
    let table = event.stageVariables ? event.stageVariables[STAGE_TABLE] : 'dnsfeedsrv';
    if (!(qs != null && QS_KEY_PARAM in qs && secret == qs[QS_KEY_PARAM])) {
        return utils.response403('Invalid or missing key');
    }
    let configFile = utils.configFileName(event);
    switch (event.requestContext.httpMethod) {
        case "GET": {
            return refreshConfigFromDatastore(table, configFile).then(r => utils.responseJson(r)).catch(e => utils.response501(e));
        }
        case "POST": {
            if (event.body == null) {
                return utils.response501("Null body in POST request.");
            }
            let configBody = {};
            try {
                configBody = JSON.parse(event.body);
            } catch (err) {
                return utils.response501("Error parsing JSON configuration content.");
            }
            if (typeof configBody != "object") {
                return utils.response501("Configuration provided is not a JSON object");
            }
            return putNewConfig(table, configFile, configBody).then(data => utils.responseJson(data)).catch(e => utils.response501(e));
        }
    }
    return utils.response501('HTTP Method not implemented.');
}
