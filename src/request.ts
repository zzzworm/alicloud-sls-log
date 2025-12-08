import type { RequestConfig, SafeRequestOptions } from "./type";
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
            // 使用 crypto-js 计算 MD5
            // CryptoJS.lib.WordArray.create 可以直接接受 Uint8Array
            const bodyWordArray = CryptoJS.lib.WordArray.create(options.body);
            headers["content-md5"] = CryptoJS.MD5(bodyWordArray).toString(CryptoJS.enc.Hex).toUpperCase();
        }
        // SLS 签名规范：
        // - POST 请求：resource 只包含 path
        // - GET 请求：resource 包含 path 和查询参数
        const resource = options.method === "GET" && options.queries
            ? formatResource(options.path, options.queries)
            : options.path;
        headers.authorization = this.sign(options.method, resource, headers);

        const url = `https://${buildProjectName(options.projectName)}${this.config.endpoint}${options.path}${buildQueries(options.queries)}`;
        
        // 使用 fetch 替代 axios
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), (options.requestOptions?.timeout || this.config.globalRequestOptions?.timeout || DEFAULT_REQUEST_OPTIONS.timeout || 3000) as number);
        
        try {
            const response = await fetch(url, {
                method: options.method,
                body: options.body || undefined,
                headers,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            const contentType = response.headers.get("content-type") || "";
            if (!contentType.startsWith("application/json")) {
                return await response.arrayBuffer();
            }

            const body: Record<string, any> = await response.json();

            if (body.errorCode && body.errorMessage) {
                throw new AliCloudSLSLogError(
                    body.errorMessage,
                    body.errorCode,
                    response.headers.get("x-log-requestid"),
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
        } catch (error: any) {
            clearTimeout(timeoutId);
            if (error.name === "AbortError") {
                throw new Error("Request timeout");
            }
            throw error;
        }
    }

    private sign(method: string, resource: string, headers: Record<string, string>): string {
        // 获取 header 值（不区分大小写查找）
        const getHeader = (key: string): string => {
            const lowerKey = key.toLowerCase();
            for (const [k, v] of Object.entries(headers)) {
                if (k.toLowerCase() === lowerKey) {
                    return v || "";
                }
            }
            return "";
        };
        
        const contentMD5 = getHeader("content-md5");
        const contentType = getHeader("content-type");
        const date = getHeader("date");
        const canonicalizedHeaders = getCanonicalizedHeaders(headers);
        
        // 构建签名字符串：METHOD\nCONTENT-MD5\nCONTENT-TYPE\nDATE\nCANONICALIZED-HEADERS\nRESOURCE
        // 如果 canonicalizedHeaders 为空，仍然需要 \n 分隔符
        const signString = `${method}\n${contentMD5}\n${contentType}\n${date}\n${canonicalizedHeaders}\n${resource}`;
        
        // 使用 crypto-js 进行 HMAC-SHA1 签名
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
    const canonicalizedKeys = Object.keys(headers)
        .filter(key => {
            const lowerKey = key.toLowerCase();
            return lowerKey.startsWith("x-log-") || lowerKey.startsWith("x-acs-");
        })
        .sort();
    
    if (canonicalizedKeys.length === 0) {
        return "";
    }
    
    return canonicalizedKeys
        .map(key => `${key.toLowerCase()}:${headers[key]!.trim()}`)
        .join("\n");
}
