import * as utils from './utils';

interface addrGroup {
    ipv4: utils.addrValidUntil,
    ipv6: utils.addrValidUntil
}

export interface fqdnLocalItem {
    [fqdn: string]: addrGroup
}

export class storage {
    localDict: fqdnLocalItem;

    constructor() {
        this.localDict = {};
    }

    hasFqdn(fqdn: string): boolean {
        return fqdn in this.localDict;
    }

    setFqdn(fqdn: string, data: addrGroup): void {
        this.localDict[fqdn] = data;
    }

    /**
     * Checks if a item evaluated in a time window should trigger a dictionary update
     * @param item An _address:string_ , _ttl:number_ pair to be evaluated against a dictionary
     * @param dict The dictionary to evaluate (_ipv4_ / _ipv6_)
     * @param span Time window to evaluate
     * @returns _true_ if the dictionary must be updated due to the item provided being new or fresher
     */
    private ttlUpdated(item: [string, number], dict: utils.addrValidUntil, span: number, currentTime: number): boolean {
        let address = item[0];
        let validUntil = item[1];
        if (!(address in dict) || currentTime - span > dict[address]) {
            dict[address] = validUntil;
            return true;
        }
        return false;
    }

    ttlUpdated4(fqdn: string, item: [string, number], span: number, currentTime: number): boolean {
        return this.ttlUpdated(item, this.localDict[fqdn].ipv4, span, currentTime);
    }

    ttlUpdated6(fqdn: string, item: [string, number], span: number, currentTime: number): boolean {
        return this.ttlUpdated(item, this.localDict[fqdn].ipv6, span, currentTime);
    }

    /**
     * Extract addresses from a dictionary (_ipv4_ / _ipv6_) given a time window
     * @param dict The dictionary to extract items from
     * @param span The evaluation time window
     * @returns The array of valid addresses from the dictionary in the provided time window
     */
    private validEntries(dict: utils.addrValidUntil, span: number, currentTime: number): string[] {
        return Object.entries(dict).filter(item => item[1] > currentTime - span).map(item => item[0]);
    }

    validEntries4(fqdn: string, span: number, currentTime: number): string[] {
        return this.validEntries(this.localDict[fqdn].ipv4, span, currentTime);
    }

    validEntries6(fqdn: string, span: number, currentTime: number): string[] {
        return this.validEntries(this.localDict[fqdn].ipv6, span, currentTime);
    }

    get4(fqdn: string): utils.addrValidUntil {
        return this.localDict[fqdn].ipv4;
    }

    get6(fqdn: string): utils.addrValidUntil {
        return this.localDict[fqdn].ipv6;
    }
}
