import * as dns from "dns";
import * as utils from "./utils";
import * as dbif from "./dydbif";
import * as st from "./localstore";

const CFGENTRYPOINT = 'config';
const STAGE_SECRET = 'secret';
const STAGE_TABLE = 'dbtable';
const QS_KEY_PARAM = 'key';
const DEFAULT_SPAN = 86400;
const DEFAULT_TTL = 60;
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

let currentTime: number;
let stagedServices: { [configName: string]: fqdnService } = {};
let dbClient: dbif.dydbif;
let storedItems: st.storage;

class fqdnService {
    serviceConfig: Object;
    private dbClient: dbif.dydbif;
    private extStore: st.storage
    responseBuffer: Response

    constructor(serviceConfig: Object, dbclient: dbif.dydbif, extStore: st.storage) {
        this.serviceConfig = serviceConfig;
        this.dbClient = dbclient;
        this.extStore = extStore;
        this.responseBuffer = {};
    }

    resetBuffer() {
        this.responseBuffer = {};
    }

    /**
     * Fetchs the values of a provided fqdn from DynamoDB and stores the addreses in the _ipv4_ and _ipv6_ dictionaries
     * @param fqdn The fqdn object requested
     * @returns a promise that populate the database with an empty entry or with data coming from DynamoDB
     */
    refreshFqdnFromDb(fqdn: string): Promise<void> {
        if (!this.extStore.hasFqdn(fqdn)) {
            return this.dbClient.safeGetById(fqdn).then(item => { this.extStore.setFqdn(fqdn, { ipv4: item.ipv4, ipv6: item.ipv6 }) });
        }
        return Promise.resolve();
    }

    /**
     * Recursive function to drill down the provided configuration file
     * @param arg JS element to process
     * @param span Time window to evaluate
     * @returns _arg_ as is or transformed if _arg_ is a _Request_
     */
    drillDown(arg: any, span: number): Promise<any> {
        if (isRequest(arg)) {
            return this.resolveDns(arg.fqdn, span);
        } else if (typeof arg == "object") {
            let keyPromises: Promise<any>[] = [];
            for (let k in arg) {
                keyPromises.push(this.drillDown(arg[k], span).then(r => arg[k] = r));
            }
            return Promise.all(keyPromises).then(() => arg);
        }
        return Promise.resolve(arg);
    }

    /**
     * Transfoms a _Request_ JS configuration entity with its corresponding _ipv4_ / _ipv6_ set of arrays given a provided time window
     * @param fqdn The fqdn object requested
     * @param span Time window to evaluate
     * @returns a promise that will resolve with the transformation
     */
    resolveDns(fqdn: string, span: number): Promise<Response> {
        return this.refreshFqdnFromDb(fqdn).then(() => {
            let localEntries: st.fqdnLocalItem = { [fqdn]: { ipv4: {}, ipv6: {} } };
            let ipv4Updated: [string, number][] = [];
            let ipv6Updated: [string, number][] = [];
            let resolvers: Promise<void>[] = [];
            resolvers.push(new Promise((resolve, reject) => {
                dns.resolve4(fqdn, { ttl: true }, (err, addr) => {
                    if (err == null) {
                        for (let i in addr) {
                            let address = addr[i].address;
                            let ttl = Number(addr[i].ttl);
                            if (isNaN(ttl) || ttl == 0) ttl = DEFAULT_TTL;
                            let validUntil = currentTime + ttl;
                            localEntries[fqdn].ipv4[address] = validUntil;
                        }
                        ipv4Updated = Object.entries(localEntries[fqdn].ipv4).filter(
                            item => this.extStore.ttlUpdated4(fqdn, item, span, currentTime));
                    }
                    resolve();
                })
            }));
            resolvers.push(new Promise((resolve, reject) => {
                dns.resolve6(fqdn, { ttl: true }, (err, addr) => {
                    if (err == null) {
                        for (let i in addr) {
                            let address = addr[i].address;
                            let ttl = Number(addr[i].ttl);
                            if (isNaN(ttl) || ttl == 0) ttl = DEFAULT_TTL;
                            let validUntil = currentTime + ttl;
                            localEntries[fqdn].ipv6[address] = validUntil;
                        }
                        ipv6Updated = Object.entries(localEntries[fqdn].ipv6).filter(
                            item => this.extStore.ttlUpdated6(fqdn, item, span, currentTime));
                    }
                    resolve();
                })
            }));
            return Promise.all(resolvers).then(() => {
                if (ipv4Updated.length + ipv6Updated.length > 0) {
                    return this.dbClient.putItem({
                        id: fqdn,
                        ipv4: this.extStore.get4(fqdn),
                        ipv6: this.extStore.get6(fqdn)
                    });
                }
                return Promise.resolve();
            });
        }).then(() => {
            let response: Response = {};
            let ipv4Entries = this.extStore.validEntries4(fqdn, span, currentTime);
            let ipv6Entries = this.extStore.validEntries6(fqdn, span, currentTime);
            if (ipv4Entries.length > 0) {
                response.ipv4 = ipv4Entries;
                this.responseBuffer.ipv4 = this.responseBuffer.ipv4 ? this.responseBuffer.ipv4.concat(ipv4Entries) : ipv4Entries;
            }
            if (ipv6Entries.length > 0) {
                response.ipv6 = ipv6Entries
                this.responseBuffer.ipv6 = this.responseBuffer.ipv6 ? this.responseBuffer.ipv6.concat(ipv6Entries) : ipv6Entries;
            };
            return response;
        });
    }
}

function fqdnServiceFactory(configFile: string, dbClient: dbif.dydbif, stor: st.storage): Promise<fqdnService> {
    return dbClient.getConfig(configFile).then(cfg => new fqdnService(cfg, dbClient, stor));
}

/**
 * AWS API GW proxy mode integration handler
 */
exports.handler = async function (event: AWSLambda.APIGatewayProxyEvent,
    context: AWSLambda.APIGatewayEventRequestContext,
    callback: AWSLambda.APIGatewayProxyCallback): Promise<AWSLambda.APIGatewayProxyResult> {

    currentTime = Date.now() / 1000 | 0;
    let stageVars = event.stageVariables;
    let missingVars = [STAGE_SECRET, STAGE_TABLE].filter(v => stageVars ? !(v in stageVars) : true);
    if (missingVars.length != 0) return utils.response501('"' + missingVars.toString() + '" stage variable(s) not set.');
    let table = event.stageVariables ? event.stageVariables[STAGE_TABLE] : 'fqdnfeedsrv';

    if (dbClient == null) {
        dbClient = new dbif.dydbif(table);
    }

    if (storedItems == null) {
        storedItems = new st.storage();
    }

    let pathTokens = event.path.split('/');
    if (pathTokens[pathTokens.length - 1] == CFGENTRYPOINT) {
        return configHandler(event, table);
    }

    let span = DEFAULT_SPAN;
    let qs = event.queryStringParameters;
    if (qs !== null && 'span' in qs) {
        let parsedScope = Number(qs['span']);
        if (!Number.isNaN(parsedScope) && parsedScope != 0) span = parsedScope;
    }

    let configFile = utils.configFileName(event);
    let fqdnServiceInstance: Promise<fqdnService>;
    if (!(configFile in stagedServices)) {
        fqdnServiceInstance = fqdnServiceFactory(configFile, dbClient, storedItems).then(fs => {
            stagedServices[configFile] = fs; return fs
        });
    } else {
        fqdnServiceInstance = Promise.resolve(stagedServices[configFile]);
    }

    return fqdnServiceInstance.then(fs => {
        fs.resetBuffer();
        let workableConfig: Object = JSON.parse(JSON.stringify(fs.serviceConfig));
        return fs.drillDown(workableConfig, span).then(processedConfig => {
            if (qs === null || qs === undefined || ("v" in qs && qs["v"] == "ipv4")) {
                return utils.responsePlain(fs.responseBuffer.ipv4 ? fs.responseBuffer.ipv4.join("\n") : "");
            } else if ("v" in qs && qs["v"] == "ipv6") {
                return utils.responsePlain(fs.responseBuffer.ipv6 ? fs.responseBuffer.ipv6.join("\n") : "");
            }
            return utils.responseJson(processedConfig);
        })
    }).catch(e => utils.response501(e));
}

/**
 * AWS API GW proxy mode integration handler for the _/config_ entry point
 */
export function configHandler(event: AWSLambda.APIGatewayProxyEvent, table: string): Promise<AWSLambda.APIGatewayProxyResult> {
    let qs = event.queryStringParameters;
    let secret = event.stageVariables ? event.stageVariables[STAGE_SECRET] : event.requestContext.requestId;
    if (!(qs != null && QS_KEY_PARAM in qs && secret == qs[QS_KEY_PARAM])) {
        return utils.response403('Invalid or missing key');
    }
    let configFile = utils.configFileName(event);
    switch (event.requestContext.httpMethod) {
        case "GET": {
            return dbClient.getConfig(configFile).then(r => utils.responseJson(r)).catch(e => utils.response501(e));
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
            return dbClient.putNewConfig(configFile, configBody).then(data => {
                if (configFile in stagedServices) {
                    stagedServices[configFile].serviceConfig = data;
                } else {
                    stagedServices[configFile] = new fqdnService(data, dbClient, storedItems);
                }
                return utils.responseJson(data);
            }).catch(e => utils.response501(e));
        }
    }
    return utils.response501('HTTP Method not implemented.');
}
