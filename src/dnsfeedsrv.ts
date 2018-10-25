// Copyright 2015-2017 Palo Alto Networks, Inc
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//       http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as dns from "dns";
import * as utils from "./utils";
import * as dbif from "./dydbif";
import * as st from "./localstore";

/**
 * If the last part of the event path value provided by the AWS API GW equals this string then
 * it will be considered a configuration request
 */
const CFGENTRYPOINT = 'config';

/**
 * AWS API GW stage variable that holds the configuration auth key
 */
const STAGE_SECRET = 'secret';

/**
 * AWS API GW stage variable that holds the DynamoDB table to be used
 */
const STAGE_TABLE = 'dbtable';

/**
 * The querystring parameter whose value should match [[STAGE_SECRET]] for the configuration request
 * to be accepted.
 */
const QS_KEY_PARAM = 'key';

/**
 * Default request span (24h = 86400s)
 */
const DEFAULT_SPAN = 86400;

/**
 * Default DNS Resolve TTL that will be applied to a response if the parser fails.
 */
const DEFAULT_TTL = 60;

/**
 * Simplistic REGEX pattern to match a fqdn
 */
const basicFqdnRegex = /^([a-z,0-9-_]+\.)+[a-z,0-9-_]+$/i;

interface Request {
    fqdn: string;
}

/**
 * Type Guard for _Request_ objects in the configuration file
 */
function isRequest(fqdn: Object | Request): fqdn is Request {
    return (<Request>fqdn).fqdn !== undefined &&
        basicFqdnRegex.exec((<Request>fqdn).fqdn) != null
}

interface Response {
    ipv4?: String[],
    ipv6?: String[]
}

/**
 * Dictionary to store configurations for many AWS API GW Stages for this lambda
 */
let stagedServices: { [configName: string]: fqdnService } = {};

/**
 * Singleton memory storage object
 */
let storedItems = new st.storage();;

/**
 * Implements the fqdnService logic
 */
class fqdnService {

    /**
     * Instance configuration
     */
    serviceConfig: Object
    /**
     * DynamoDB client
     */
    dbClient: dbif.dydbif;

    /**
     * Temporary buffer to store all IPv4 and IPv6 addresses discovered while drilling down
     * the configuration.
     */
    responseBuffer: Response

    /**
     * 
     * @param serviceConfig fqdn service configuration file
     * @param dbClient DynamoDB client
     */
    constructor(configFile: string, serviceConfig: Object, dbClient: dbif.dydbif) {
        this.serviceConfig = serviceConfig;
        this.dbClient = dbClient;
        this.responseBuffer = {};
    }

    private res4wraper(fqdn: string): Promise<dns.RecordWithTtl[]> {
        return new Promise((resolve, reject) => {
            dns.resolve4(fqdn, { ttl: true }, (err, addr) => {
                if (err == null) {
                    resolve(addr);
                    return;
                }
                resolve([]);
            })
        })
    }

    private res6wraper(fqdn: string): Promise<dns.RecordWithTtl[]> {
        return new Promise((resolve, reject) => {
            dns.resolve6(fqdn, { ttl: true }, (err, addr) => {
                if (err == null) {
                    resolve(addr);
                    return;
                }
                resolve([]);
            })
        })
    }

    /**
     * Fetchs the values of a provided fqdn from DynamoDB and stores the addreses in the _ipv4_ and _ipv6_ dictionaries
     * @param fqdn The fqdn object requested
     * @returns a promise that populate the database with an empty entry or with data coming from DynamoDB
     */
    private async refreshFqdnFromDb(fqdn: string): Promise<void> {
        if (!storedItems.hasFqdn(fqdn)) {
            let item = await this.dbClient.safeGetById(fqdn);
            storedItems.setFqdn(fqdn, { ipv4: item.ipv4, ipv6: item.ipv6 });
        }
    }

    /**
     * Triggers the fqdn service config file processing resolving all _requests_ with dns _responses_
     * @param span Time window. Additional IPv4/IPv6 addresses in the local storage with a _valid until_ value greater than
     * [[utils.currentTime()]] - [[span]] will be added to the response.
     * @returns a copy of the [[serviceConfig]] configuration with all requests replaced with IPv4 and IPv6 arrays
     */
    process(span: number): Promise<any> {
        this.responseBuffer = {};
        let workableConfig: Object = JSON.parse(JSON.stringify(this.serviceConfig));
        return this.drillDown(workableConfig, span);
    }

    /**
     * Recursive function to drill down the provided configuration file
     * @param arg JS element to process
     * @param span Time window to evaluate
     * @returns _arg_ as is or transformed if _arg_ is a _Request_
     */
    private drillDown(arg: any, span: number): Promise<any> {
        if (isRequest(arg)) {
            return this.resolveDns(arg.fqdn, span);
        } else if (typeof arg == "object") {
            let promisePool: Promise<any>[] = [];
            for (let k in arg) {
                promisePool.push(this.drillDown(arg[k], span).then(a => arg[k] = a));
            }
            return Promise.all(promisePool).then(() => arg);
        }
        return Promise.resolve(arg);
    }

    /**
     * Transfoms a _Request_ JS configuration entity with its corresponding _ipv4_ / _ipv6_ set of arrays. Addresses coming from
     * dns resolution will always be part of the response. Additional addresses in the local storage that are also valid in the
     * provided time window will also be attached to the response.
     * @param fqdn The fqdn object requested
     * @param span Time window to evaluate
     * @returns a promise that will resolve with the transformation
     */
    private async resolveDns(fqdn: string, span: number): Promise<Response> {
        await this.refreshFqdnFromDb(fqdn);
        let localEntries: st.fqdnLocalItem = { [fqdn]: { ipv4: {}, ipv6: {} } };
        let ipv4Updated: [string, number][] = [];
        let ipv6Updated: [string, number][] = [];
        let addr4 = await this.res4wraper(fqdn);
        for (let i in addr4) {
            let address = addr4[i].address;
            let ttl = Number(addr4[i].ttl);
            if (isNaN(ttl) || ttl == 0) ttl = DEFAULT_TTL;
            let validUntil = utils.currentTime() + ttl;
            localEntries[fqdn].ipv4[address] = validUntil;
        }
        // Keep only these ipv4 addresses in the response that 1) are not known to the local storage or 2) wouldn't be
        // selected due to expired TTL. The [[ttlUpdated4]] method takes advantage of the opportunity to update the local
        // storage with these entries.
        ipv4Updated = Object.entries(localEntries[fqdn].ipv4).filter(
            item => storedItems.ttlUpdated4(fqdn, item, span));
        let addr6 = await this.res6wraper(fqdn);
        for (let i in addr6) {
            let address = addr6[i].address;
            let ttl = Number(addr6[i].ttl);
            if (isNaN(ttl) || ttl == 0) ttl = DEFAULT_TTL;
            let validUntil = utils.currentTime() + ttl;
            localEntries[fqdn].ipv6[address] = validUntil;
        }
        ipv6Updated = Object.entries(localEntries[fqdn].ipv6).filter(
            item => storedItems.ttlUpdated6(fqdn, item, span));

        if (ipv4Updated.length + ipv6Updated.length > 0)
            this.dbClient.putItem({
                id: fqdn,
                ipv4: storedItems.get4(fqdn),
                ipv6: storedItems.get6(fqdn)
            });

        // Time to format and return a response with valid entries from the local storage.
        let response: Response = {};
        let ipv4Entries = storedItems.validEntries4(fqdn, span);
        let ipv6Entries = storedItems.validEntries6(fqdn, span);
        if (ipv4Entries.length > 0) {
            response.ipv4 = ipv4Entries;
            this.responseBuffer.ipv4 = this.responseBuffer.ipv4 ?
                this.responseBuffer.ipv4.concat(ipv4Entries) : ipv4Entries;
        }
        if (ipv6Entries.length > 0) {
            response.ipv6 = ipv6Entries
            this.responseBuffer.ipv6 = this.responseBuffer.ipv6 ?
                this.responseBuffer.ipv6.concat(ipv6Entries) : ipv6Entries;
        };
        return response;
    }
}

/**
 * [[fqdnService]] object async instantiation factory
 * @param table DynamoDB table this service must work on
 * @param configFile ID of the config file inside DynamoDB this service instance should work with
 * @returns a promise the instance will be created with the configuration body retrieved from DynamoDB
 */
async function fqdnServiceFactory(table: string, configFile: string): Promise<fqdnService> {
    let dbClient = new dbif.dydbif(table);
    let configBody = await dbClient.getConfig(configFile);
    return new fqdnService(configFile, configBody, dbClient);
}

/**
 * AWS API GW proxy mode integration handler
 */
exports.handler = async function (event: AWSLambda.APIGatewayProxyEvent,
    context: AWSLambda.APIGatewayEventRequestContext,
    callback: AWSLambda.APIGatewayProxyCallback): Promise<AWSLambda.APIGatewayProxyResult> {

    utils.setCurrentTime(); // Update current time for this transaction

    // Try to retrieve mandatory AWS API GW stage variables
    let stageVars = event.stageVariables;
    let missingVars = [STAGE_SECRET, STAGE_TABLE].filter(v => stageVars ? !(v in stageVars) : true);
    if (missingVars.length != 0) return utils.response501('"' + missingVars.toString() + '" stage variable(s) not set.');
    let table = event.stageVariables ? event.stageVariables[STAGE_TABLE] : 'fqdnfeedsrv';

    // service config name (id) is a unique value composed by the AWS API GW id and stage strings
    let configFile = utils.configFileName(event);

    // check if the request should be managed by the _configuration_ handler
    let pathTokens = event.path.split('/');
    if (pathTokens[pathTokens.length - 1] == CFGENTRYPOINT) {
        return configHandler(event, table, configFile);
    }

    let fs: fqdnService;
    // get the configuration either from the local repository (cached) or for DynamoDB (first time after module initialization)
    if (configFile in stagedServices) {
        fs = stagedServices[configFile];
    } else {
        try {
            fs = await fqdnServiceFactory(table, configFile);
        } catch (e) {
            return utils.response501(e);
        }
        stagedServices[configFile] = fs;
    }

    // extract optional [[DEFAULT_SPAN]] query parameter
    let span = DEFAULT_SPAN;
    let qs = event.queryStringParameters;
    if (qs !== null && 'span' in qs) {
        let parsedScope = Number(qs['span']);
        if (!Number.isNaN(parsedScope) && parsedScope != 0) span = parsedScope;
    }

    // format a response or return a 501 error code if anything in the promise chain goes wrong
    try {
        let processedConfig = await fs.process(span);
        if (qs === null || qs === undefined || ("v" in qs && qs["v"] == "ipv4")) {
            return utils.responsePlain(fs.responseBuffer.ipv4 ? fs.responseBuffer.ipv4.join("\n") : "");
        } else if ("v" in qs && qs["v"] == "ipv6") {
            return utils.responsePlain(fs.responseBuffer.ipv6 ? fs.responseBuffer.ipv6.join("\n") : "");
        }
        return utils.responseJson(processedConfig);
    } catch (e) {
        return utils.response501(e);
    }
}

/**
 * AWS API GW proxy mode integration handler for the _/config_ entry point
 */
export async function configHandler(event: AWSLambda.APIGatewayProxyEvent,
    table: string,
    configFile: string): Promise<AWSLambda.APIGatewayProxyResult> {
    let qs = event.queryStringParameters;
    let secret = event.stageVariables ? event.stageVariables[STAGE_SECRET] : event.requestContext.requestId;
    if (!(qs != null && QS_KEY_PARAM in qs && secret == qs[QS_KEY_PARAM])) {
        return utils.response403('Invalid or missing key');
    }
    switch (event.requestContext.httpMethod) {
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
            let fs: fqdnService;
            // get the configuration either from the local repository (cached) or for DynamoDB (first time after module initialization)
            if (configFile in stagedServices) {
                fs = stagedServices[configFile];
                try {
                    await fs.dbClient.putNewConfig(configFile, configBody);
                } catch (e) {
                    return utils.response501(e);
                }
                stagedServices[configFile].serviceConfig = configBody;
                return utils.responseJson(configBody);
            }
            let dbClient = new dbif.dydbif(table);
            try {
                await dbClient.putNewConfig(configFile, configBody);
            } catch (e) {
                return utils.response501(e);
            }
            stagedServices[configFile] = new fqdnService(configFile, configBody, dbClient);
            try {
                fs = await fqdnServiceFactory(table, configFile);
            } catch (e) {
                return utils.response501(e);
            }
            stagedServices[configFile] = fs;
        }
    }
    return utils.response501('HTTP Method not implemented.');
}
