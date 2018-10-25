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

export const DBKEY = 'id';

export interface addrValidUntil {
    [address: string]: number
}

let cTime: number = 0;

export function currentTime(): number {
    return cTime;
}

export function setCurrentTime(): void {
    cTime = Date.now() / 1000 | 0;
}

function apiGwResponse(code: number, type: string, message: string): Promise<AWSLambda.APIGatewayProxyResult> {
    return Promise.resolve({
        statusCode: code,
        body: message,
        headers: {
            "Content-Type": type,
            "Content-Length": message.length
        }
    });
}

export function response501(message: string): Promise<AWSLambda.APIGatewayProxyResult> {
    return apiGwResponse(501, "text/plain", message);
}

export function response403(message: string): Promise<AWSLambda.APIGatewayProxyResult> {
    return apiGwResponse(403, "text/plain", message);
}

export function responseJson(payload: Object): Promise<AWSLambda.APIGatewayProxyResult> {
    return apiGwResponse(200, "application/json", JSON.stringify(payload));
}

export function responsePlain(message: string): Promise<AWSLambda.APIGatewayProxyResult> {
    return apiGwResponse(200, "text/plain", message);
}

export function configFileName(event: AWSLambda.APIGatewayProxyEvent): string {
    return "cfg:" + event.requestContext.apiId + ":" + event.requestContext.stage;
}
