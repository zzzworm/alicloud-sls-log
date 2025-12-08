import type { RequestConfig, SafeRequestOptions } from "./type";
import axios from "axios";
import CryptoJS from "crypto-js";
import qs from "qs";

const DEFAULT_REQUEST_OPTIONS: SafeRequestOptions = {
    timeout: 3000,
    validateStatus: () => true,
};

interface RequestOptions {
    method: "POST" | "GET" | "PUT" | "DELETE";
    path: string;
    queries?: Record<string, any>;
    body?: Uint8Array;
    headers?: Record<string, string>;
    projectName?: string;
    requestOptions?: SafeRequestOptions;
}

export class AliCloudSLSLogError extends Error {
    constructor(
        message: string,
        public readonly code: string,
        public readonly requestid: string | null,
    ) {
        super(message);
        this.name = `${code}Error`;
    }
}

export class Request {
    public constructor(private readonly config: RequestConfig) {
    }

    public updateCredential(accessKeyID: string, accessKeySecret: string, stsToken?: string): void {
        this.config.accessKeyID = accessKeyID;
        this.config.accessKeySecret = accessKeySecret;
        this.config.stsToken = stsToken;
    }

    protected async do(options: RequestOptions): Promise<any> {
        const headers: Record<string, string> = Object.assign({
            "content-type": "application/json",
            "date": new Date().toUTCString(),
            "x-log-apiversion": "0.6.0",
            "x-log-signaturemethod": "hmac-sha1",
        }, options.headers);

        if (this.config.stsToken) {
            headers["x-acs-security-token"] = this.config.stsToken;
        }

        if (options.body) {
            headers["content-length"] = options.body.length.toString();
            headers["content-md5"] = CryptoJS.MD5(CryptoJS.lib.WordArray.create(options.body)).toString(CryptoJS.enc.Hex).toUpperCase();
        }
        headers.authorization = this.sign(options.method, formatResource(options.path, options.queries), headers);

        const url = `http://${buildProjectName(options.projectName)}${this.config.endpoint}${options.path}${buildQueries(options.queries)}`;
        console.warn(url);
        const response = await axios(url, {
            method: options.method,
            data: options.body,
            headers,
            ...DEFAULT_REQUEST_OPTIONS,
            ...this.config.globalRequestOptions,
            ...options.requestOptions,
        });

        const contentType = response.headers["content-type"] || "";
        if (!contentType.startsWith("application/json")) {
            return response.data;
        }

        const body: Record<string, any> = response.data;

        if (body.errorCode && body.errorMessage) {
            throw new AliCloudSLSLogError(
                body.errorMessage,
                body.errorCode,
                response.headers["x-log-requestid"],
            );
        }

        if (body.Error) {
            throw new AliCloudSLSLogError(
                body.Error.Message,
                body.Error.Code,
                body.Error.RequestId,
            );
        }

        return body;
    }

    private sign(method: string, resource: string, headers: Record<string, string>): string {
        const contentMD5 = headers["content-md5"] || "";
        const contentType = headers["content-type"] || "";
        const date = headers.date;
        const canonicalizedHeaders = getCanonicalizedHeaders(headers);
        const signString = `${method}\n${contentMD5}\n${contentType}\n`
            + `${date}\n${canonicalizedHeaders}\n${resource}`;
        const signature = CryptoJS.HmacSHA1(signString, this.config.accessKeySecret).toString(CryptoJS.enc.Base64);

        return `LOG ${this.config.accessKeyID}:${signature}`;
    }
}

function buildQueries(queries?: Record<string, any>): string {
    const str = qs.stringify(queries);
    return str ? `?${str}` : "";
}

function buildProjectName(projectName?: string): string {
    return projectName ? `${projectName}.` : "";
}

function formatString(value: any): string {
    if (typeof value === "undefined") {
        return "";
    }

    return String(value);
}

function formatResource(path: string, queries?: Record<string, any>): string {
    if (!queries) {
        return path;
    }

    const keys = Object.keys(queries);
    if (!keys.length) {
        return path;
    }

    const queryStr = keys
        .sort()
        .map(key => `${key}=${formatString(queries[key])}`)
        .join("&");

    return `${path}?${queryStr}`;
}

function getCanonicalizedHeaders(headers: Record<string, string>): string {
    return Object.keys(headers)
        .filter(key => key.startsWith("x-log-") || key.startsWith("x-acs-"))
        .sort()
        .map(key => `${key}:${headers[key]!.trim()}`)
        .join("\n");
}
