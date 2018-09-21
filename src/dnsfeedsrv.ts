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
 * Singleton client interface to the database it will be instantiated the first time AWS API GW invokes the handler
 */
let dbClient: dbif.dydbif;

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
    serviceConfig: Object;

    /**
     * Temporary buffer to store all IPv4 and IPv6 addresses discovered while drilling down
     * the configuration.
     */
    responseBuffer: Response

    /**
     * 
     * @param serviceConfig fqdn service configuration file
     */
    constructor(serviceConfig: Object) {
        this.serviceConfig = serviceConfig;
        this.responseBuffer = {};
    }

    /**
     * Fetchs the values of a provided fqdn from DynamoDB and stores the addreses in the _ipv4_ and _ipv6_ dictionaries
     * @param fqdn The fqdn object requested
     * @returns a promise that populate the database with an empty entry or with data coming from DynamoDB
     */
    private refreshFqdnFromDb(fqdn: string): Promise<void> {
        if (!storedItems.hasFqdn(fqdn)) {
            return dbClient.safeGetById(fqdn).then(item => { storedItems.setFqdn(fqdn, { ipv4: item.ipv4, ipv6: item.ipv6 }) });
        }
        return Promise.resolve();
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
            let keyPromises: Promise<any>[] = [];
            for (let k in arg) {
                keyPromises.push(this.drillDown(arg[k], span).then(r => arg[k] = r));
            }
            return Promise.all(keyPromises).then(() => arg);
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
    private resolveDns(fqdn: string, span: number): Promise<Response> {
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
                            let validUntil = utils.currentTime() + ttl;
                            localEntries[fqdn].ipv4[address] = validUntil;
                        }
                        // Keep only these ipv4 addresses in the response that 1) are not known to the local storage or 2) wouldn't be
                        // selected due to expired TTL. The [[ttlUpdated4]] method takes advantage of the opportunity to update the local
                        // storage with these entries.
                        ipv4Updated = Object.entries(localEntries[fqdn].ipv4).filter(
                            item => storedItems.ttlUpdated4(fqdn, item, span));
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
                            let validUntil = utils.currentTime() + ttl;
                            localEntries[fqdn].ipv6[address] = validUntil;
                        }
                        ipv6Updated = Object.entries(localEntries[fqdn].ipv6).filter(
                            item => storedItems.ttlUpdated6(fqdn, item, span));
                    }
                    resolve();
                })
            }));
            return Promise.all(resolvers).then(() => {
                // If we have updated items then it is time to update the fqdn in the DynamoDB Table
                if (ipv4Updated.length + ipv6Updated.length > 0) {
                    return dbClient.putItem({
                        id: fqdn,
                        ipv4: storedItems.get4(fqdn),
                        ipv6: storedItems.get6(fqdn)
                    });
                }
                return Promise.resolve();
            });
        }).then(() => {
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
        });
    }
}

/**
 * [[fqdnService]] object async instantiation factory
 * @param configFile ID of the config file inside DynamoDB this service instance should work with
 * @returns a promise the instance will be created with the configuration body retrieved from DynamoDB
 */
function fqdnServiceFactory(configFile: string): Promise<fqdnService> {
    return dbClient.getConfig(configFile).then(cfg => new fqdnService(cfg));
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

    // dbclient singleton initialization
    if (dbClient == null) {
        dbClient = new dbif.dydbif(table);
    }

    // check if the request should be managed by the _configuration_ handler
    let pathTokens = event.path.split('/');
    if (pathTokens[pathTokens.length - 1] == CFGENTRYPOINT) {
        return configHandler(event, table);
    }

    // extract optional [[DEFAULT_SPAN]] query parameter
    let span = DEFAULT_SPAN;
    let qs = event.queryStringParameters;
    if (qs !== null && 'span' in qs) {
        let parsedScope = Number(qs['span']);
        if (!Number.isNaN(parsedScope) && parsedScope != 0) span = parsedScope;
    }

    // service config name (id) is a unique value composed by the AWS API GW id and stage strings
    let configFile = utils.configFileName(event);
    let fqdnServiceInstance: Promise<fqdnService>;
    // get the configuration either from the local repository (cached) or for DynamoDB (first time after module initialization)
    if (configFile in stagedServices) {
        fqdnServiceInstance = Promise.resolve(stagedServices[configFile]);
    } else {
        fqdnServiceInstance = fqdnServiceFactory(configFile).then(fs => {
            stagedServices[configFile] = fs; return fs
        });
    }

    // format a response or return a 501 error code if anything in the promise chain goes wrong
    return fqdnServiceInstance.then(fs => {
        return fs.process(span).then(processedConfig => {
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
                    stagedServices[configFile] = new fqdnService(data);
                }
                return utils.responseJson(data);
            }).catch(e => utils.response501(e));
        }
    }
    return utils.response501('HTTP Method not implemented.');
}
