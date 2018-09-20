import * as dns from "dns";
import * as utils from "./utils";
import * as dbif from "./dydbif";

const CFGENTRYPOINT = 'config';
const DEFAULT_SPAN = 86400;
const DEFAULT_TTL = 60;
const basicFqdnRegex = /^([a-z,0-9-_]+\.)+[a-z,0-9-_]+$/i;


interface Request {
    fqdn: string;
}

interface Response {
    ipv4?: String[],
    ipv6?: String[]
}

interface fqdnLocalItem {
    [fqdn: string]: {
        ipv4: dbif.addrValidUntil,
        ipv6: dbif.addrValidUntil
    }
}

let dbEntries: fqdnLocalItem = {};
let currentTime: number;

/**
 * Checks if a item evaluated in a time window should trigger a dictionary update
 * @param item An _address:string_ , _ttl:number_ pair to be evaluated against a dictionary
 * @param dict The dictionary to evaluate (_ipv4_ / _ipv6_)
 * @param span Time window to evaluate
 * @returns _true_ if the dictionary must be updated due to the item provided being new or fresher
 */
function ttlUpdated(item: [string, number], dict: dbif.addrValidUntil, span: number): boolean {
    let address = item[0];
    let validUntil = item[1];
    if (!(address in dict) || currentTime - span > dict[address]) {
        dict[address] = validUntil;
        return true;
    }
    return false;
}

/**
 * Extract addresses from a dictionary (_ipv4_ / _ipv6_) given a time window
 * @param dict The dictionary to extract items from
 * @param span The evaluation time window
 * @returns The array of valid addresses from the dictionary in the provided time window
 */
function validEntries(dict: dbif.addrValidUntil, span: number): string[] {
    return Object.entries(dict).filter(item => item[1] > currentTime - span).map(item => item[0]);
}

/**
 * Type Guard for _Request_ objects in the configuration file
 */
function isRequest(fqdn: Object | Request): fqdn is Request {
    return (<Request>fqdn).fqdn !== undefined &&
        basicFqdnRegex.exec((<Request>fqdn).fqdn) != null
}

/**
 * Fetchs the values of a provided fqdn from DynamoDB and stores the addreses in the _ipv4_ and _ipv6_ dictionaries
 * @param table DynamoDB table to be used in the search
 * @param fqdn The fqdn object requested
 * @returns a promise that populate the database with an empty entry or with data coming from DynamoDB
 */
function refreshFqdnFromDb(table: string, fqdn: string): Promise<void> {
    if (!(fqdn in dbEntries)) {
        return dbif.safeGetById(table, fqdn).then(item => { dbEntries[fqdn] = { ipv4: item.ipv4, ipv6: item.ipv6 } });
    }
    return Promise.resolve();
}

/**
 * Transfoms a _Request_ JS configuration entity with its corresponding _ipv4_ / _ipv6_ set of arrays given a provided time window
 * @param table DynamoDB table to be used in the search
 * @param fqdn The fqdn object requested
 * @param span Time window to evaluate
 * @param collectedResponse A collection of _ipv4_ and _ipv6_ addresses discoverd during the configuration file drill down processing
 * @returns a promise that will resolve with the transformation
 */
function resolveDns(table: string, fqdn: string, span: number, collectedResponse: Response): Promise<Response> {
    return refreshFqdnFromDb(table, fqdn).then(() => {
        let localEntries: fqdnLocalItem = { [fqdn]: { ipv4: {}, ipv6: {} } };
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
                    ipv4Updated = Object.entries(localEntries[fqdn].ipv4).filter(item => ttlUpdated(item, dbEntries[fqdn].ipv4, span));
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
                    ipv6Updated = Object.entries(localEntries[fqdn].ipv6).filter(item => ttlUpdated(item, dbEntries[fqdn].ipv6, span));
                }
                resolve();
            })
        }));
        return Promise.all(resolvers).then(() => {
            if (ipv4Updated.length + ipv6Updated.length > 0) {
                return dbif.putItem(table, {
                    id: fqdn,
                    ipv4: dbEntries[fqdn].ipv4,
                    ipv6: dbEntries[fqdn].ipv6
                });
            }
            return Promise.resolve();
        });
    }).then(() => {
        let response: Response = {};
        let ipv4Entries = validEntries(dbEntries[fqdn].ipv4, span);
        let ipv6Entries = validEntries(dbEntries[fqdn].ipv6, span);
        if (ipv4Entries.length > 0) {
            response.ipv4 = ipv4Entries;
            collectedResponse.ipv4 = collectedResponse.ipv4 ? collectedResponse.ipv4.concat(ipv4Entries) : ipv4Entries;
        }
        if (ipv6Entries.length > 0) {
            response.ipv6 = ipv6Entries
            collectedResponse.ipv6 = collectedResponse.ipv6 ? collectedResponse.ipv6.concat(ipv6Entries) : ipv6Entries;
        };
        return response;
    });
}

/**
 * Recursive function to drill down the provided configuration file
 * @param table DynamoDB table to be used in the search
 * @param arg JS element to process
 * @param span Time window to evaluate
 * @param collectedResponse A collection of _ipv4_ and _ipv6_ addresses discoverd during the configuration file drill down processing
 * @returns _arg_ as is or transformed if _arg_ is a _Request_
 */
function drillDown(table: string, arg: any, span: number, collectedResponse: Response): Promise<any> {
    if (isRequest(arg)) {
        return resolveDns(table, arg.fqdn, span, collectedResponse);
    } else if (typeof arg == "object") {
        let keyPromises: Promise<any>[] = [];
        for (let k in arg) {
            keyPromises.push(drillDown(table, arg[k], span, collectedResponse).then(r => arg[k] = r));
        }
        return Promise.all(keyPromises).then(() => arg);
    }
    return Promise.resolve(arg);
}

/**
 * AWS API GW proxy mode integration handler
 */
exports.handler = async function (event: AWSLambda.APIGatewayProxyEvent,
    context: AWSLambda.APIGatewayEventRequestContext,
    callback: AWSLambda.APIGatewayProxyCallback): Promise<AWSLambda.APIGatewayProxyResult> {

    currentTime = Date.now() / 1000 | 0;
    let collectedResponse: Response = {};
    let stageVars = event.stageVariables;
    let missingVars = [dbif.STAGE_SECRET, dbif.STAGE_TABLE].filter(v => stageVars ? !(v in stageVars) : true);
    if (missingVars.length != 0) return utils.response501('"' + missingVars.toString() + '" stage variable(s) not set.');
    let table = event.stageVariables ? event.stageVariables[dbif.STAGE_TABLE] : 'dnsfeedsrv';
    let pathTokens = event.path.split('/');
    if (pathTokens[pathTokens.length - 1] == CFGENTRYPOINT) {
        return dbif.configHandler(event);
    }

    let span = DEFAULT_SPAN;
    let qs = event.queryStringParameters;
    if (qs !== null && 'span' in qs) {
        let parsedScope = Number(qs['span']);
        if (!Number.isNaN(parsedScope) && parsedScope != 0) span = parsedScope;
    }

    return dbif.getConfig(table, utils.configFileName(event)).then(db => drillDown(table, db, span, collectedResponse).then(() => db)).then(db => {
        if (qs === null || qs === undefined || ("v" in qs && qs["v"] == "ipv4")) {
            return utils.responsePlain(collectedResponse.ipv4 ? collectedResponse.ipv4.join("\n") : "");
        } else if ("v" in qs && qs["v"] == "ipv6") {
            return utils.responsePlain(collectedResponse.ipv6 ? collectedResponse.ipv6.join("\n") : "");
        }
        return utils.responseJson(db);
    }).catch(e => utils.response501(e));
}
