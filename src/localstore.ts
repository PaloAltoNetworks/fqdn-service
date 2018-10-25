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
     * Checks if a item evaluated in a time window should trigger a dictionary update. Take advantage of the opportunity to update the
     * local storage if needed
     * @param item An _address:string_ , _ttl:number_ pair to be evaluated against a dictionary
     * @param dict The dictionary to evaluate (_ipv4_ / _ipv6_)
     * @param span Time window to evaluate
     * @returns _true_ if the dictionary must be updated due to the item provided being new or fresher
     */
    private ttlUpdated(item: [string, number], dict: utils.addrValidUntil, span: number): boolean {
        let address = item[0];
        let validUntil = item[1];
        if (!(address in dict) || utils.currentTime() - span > dict[address]) {
            dict[address] = validUntil;
            return true;
        }
        return false;
    }

    ttlUpdated4(fqdn: string, item: [string, number], span: number): boolean {
        return this.ttlUpdated(item, this.localDict[fqdn].ipv4, span);
    }

    ttlUpdated6(fqdn: string, item: [string, number], span: number): boolean {
        return this.ttlUpdated(item, this.localDict[fqdn].ipv6, span);
    }

    /**
     * Extract addresses from a dictionary (_ipv4_ / _ipv6_) given a time window
     * @param dict The dictionary to extract items from
     * @param span The evaluation time window
     * @returns The array of valid addresses from the dictionary in the provided time window
     */
    private validEntries(dict: utils.addrValidUntil, span: number): string[] {
        return Object.entries(dict).filter(item => item[1] > utils.currentTime() - span).map(item => item[0]);
    }

    validEntries4(fqdn: string, span: number): string[] {
        return this.validEntries(this.localDict[fqdn].ipv4, span);
    }

    validEntries6(fqdn: string, span: number): string[] {
        return this.validEntries(this.localDict[fqdn].ipv6, span);
    }

    get4(fqdn: string): utils.addrValidUntil {
        return this.localDict[fqdn].ipv4;
    }

    get6(fqdn: string): utils.addrValidUntil {
        return this.localDict[fqdn].ipv6;
    }
}
