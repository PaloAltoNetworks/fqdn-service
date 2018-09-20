export const DBKEY = 'id';

export interface addrValidUntil {
    [address: string]: number
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
