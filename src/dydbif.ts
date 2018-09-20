import * as aws from 'aws-sdk';
import * as utils from './utils';

interface fqdnDbItem {
    [utils.DBKEY]: string,
    ipv4: utils.addrValidUntil,
    ipv6: utils.addrValidUntil
}

let docuClient = new aws.DynamoDB.DocumentClient();

export class dydbif {
    private tableName: string;

    /**
     * 
     * @param table DynamoDB table to use
     */
    constructor(table: string) {
        this.tableName = table;
    }

    /**
     * Fetches a configuration file from DynamoDB
     * @param configFile Config file name
     * @returns A promise that resolves to the configuration file content
     */
    getConfig(configFile: string): Promise<Object> {
        return new Promise<Object>((resolve, reject) => docuClient.get({
            TableName: this.tableName,
            Key: {
                [utils.DBKEY]: configFile
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
                resolve(JSON.parse(JSON.stringify(configBody['config'] as Object)));
            }
        }));
    }

    /**
     * Stores a new configuration file in DynamoDB
     * @param configFile Config file name
     * @param configBody Configuration file content
     * @returns a promise that will resolve with the configuration file content (echo back)
     */
    putNewConfig(configFile: string, configBody: Object): Promise<aws.DynamoDB.DocumentClient.PutItemOutput> {
        return new Promise<aws.DynamoDB.DocumentClient.PutItemOutput>((resolve, reject) => docuClient.put({
            TableName: this.tableName,
            Item: {
                [utils.DBKEY]: configFile,
                config: configBody
            }
        }, (err, data) => {
            if (err != null) {
                reject(err.message);
            } else {
                resolve(configBody);
            }
        }))
    }

    /**
     * Retrieves a fqdn document content from DynamoDB.
     * If the object does not exists an empty response is provided
     * @param id the fqdn string
     */
    safeGetById(id: string): Promise<fqdnDbItem> {
        return new Promise<fqdnDbItem>((resolve, reject) => docuClient.get({
            TableName: this.tableName,
            Key: {
                [utils.DBKEY]: id
            }
        }, (err, data) => {
            if (err != null || data == null || !("Item" in data)) {
                resolve({ [utils.DBKEY]: id, ipv4: {}, ipv6: {} });
            } else {
                resolve(data.Item as fqdnDbItem);
            }
        }))
    }

    /**
     * Stores a new fqdn document in DynamoDB
     * @param item fqdn document to be stored
     * @returns a promise that the item will be stored
     */
    putItem(item: fqdnDbItem): Promise<void> {
        return new Promise<void>((resolve, reject) => docuClient.put({
            TableName: this.tableName,
            Item: item
        }, (err, data) => {
            if (err != null) {
                reject(err.message);
            } else {
                resolve();
            }
        }));
    }
}
