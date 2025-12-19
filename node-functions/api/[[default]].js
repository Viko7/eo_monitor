import express from 'express';
import path from 'path';
import fs from 'fs';
import 'dotenv/config';
// import { fileURLToPath } from 'url';
import { teo } from "tencentcloud-sdk-nodejs-teo";
import { CommonClient } from "tencentcloud-sdk-nodejs-common";

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

const app = express();

// Function to read keys
function getKeys() {
    // 1. Try Environment Variables first
    let secretId = process.env.SECRET_ID;
    let secretKey = process.env.SECRET_KEY;

    if (secretId && secretKey) {
        return { secretId, secretKey };
    }

    // 2. Try key.txt if Env Vars are missing
    try {
        // const keyPath = path.resolve(__dirname, '../../key.txt');
        const keyPath = path.resolve(process.cwd(), 'key.txt');
        
        if (fs.existsSync(keyPath)) {
            const content = fs.readFileSync(keyPath, 'utf-8');
            const lines = content.split('\n');
            
            lines.forEach(line => {
                if (line.includes('SecretId') && !secretId) {
                    secretId = line.split('：')[1].trim();
                }
                if (line.includes('SecretKey') && !secretKey) {
                    secretKey = line.split('：')[1].trim();
                }
            });
        }
    } catch (err) {
        console.error("Error reading key.txt:", err);
    }

    return { secretId, secretKey };
}

// Metrics that belong to DescribeTimingL7OriginPullData
const ORIGIN_PULL_METRICS = [
    'l7Flow_outFlux_hy',
    'l7Flow_outBandwidth_hy',
    'l7Flow_request_hy',
    'l7Flow_inFlux_hy',
    'l7Flow_inBandwidth_hy'
];

// Metrics that belong to DescribeTopL7AnalysisData
const TOP_ANALYSIS_METRICS = [
    'l7Flow_outFlux_country',
    'l7Flow_outFlux_province',
    'l7Flow_outFlux_statusCode',
    'l7Flow_outFlux_domain',
    'l7Flow_outFlux_url',
    'l7Flow_outFlux_resourceType',
    'l7Flow_outFlux_sip',
    'l7Flow_outFlux_referers',
    'l7Flow_outFlux_ua_device',
    'l7Flow_outFlux_ua_browser',
    'l7Flow_outFlux_ua_os',
    'l7Flow_outFlux_ua',
    'l7Flow_request_country',
    'l7Flow_request_province',
    'l7Flow_request_statusCode',
    'l7Flow_request_domain',
    'l7Flow_request_url',
    'l7Flow_request_resourceType',
    'l7Flow_request_sip',
    'l7Flow_request_referers',
    'l7Flow_request_ua_device',
    'l7Flow_request_ua_browser',
    'l7Flow_request_ua_os',
    'l7Flow_request_ua'
];

// Metrics that belong to DescribeWebProtectionData (DDoS/Security)
const SECURITY_METRICS = [
    'ccAcl_interceptNum',
    'ccManage_interceptNum',
    'ccRate_interceptNum'
];

app.get('/config', (req, res) => {
    res.json({
        siteName: process.env.SITE_NAME || 'AcoFork 的 EdgeOne 监控大屏'
    });
});

app.get('/traffic', async (req, res) => {
    try {
        const { secretId, secretKey } = getKeys();
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }

        const TeoClient = teo.v20220901.Client;
        const clientConfig = {
            credential: {
                secretId: secretId,
                secretKey: secretKey,
            },
            region: "",
            profile: {
                httpProfile: {
                    endpoint: "teo.tencentcloudapi.com",
                },
            },
        };

        const client = new TeoClient(clientConfig);
        
        const now = new Date();
        const formatDate = (date) => {
             return date.toISOString().slice(0, 19) + 'Z';
        };

        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const metric = req.query.metric || "l7Flow_flux";
        const startTime = req.query.startTime || formatDate(yesterday);
        const endTime = req.query.endTime || formatDate(now);
        const interval = req.query.interval;

        let params = {};
        let data;

        console.log(`Requesting metric: ${metric}, StartTime: ${startTime}, EndTime: ${endTime}, Interval: ${interval}`);

        if (TOP_ANALYSIS_METRICS.includes(metric)) {
            // API: DescribeTopL7AnalysisData
            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricName": metric,
                "ZoneIds": [ "*" ]
            };
            console.log("Calling DescribeTopL7AnalysisData with params:", JSON.stringify(params, null, 2));
            data = await client.DescribeTopL7AnalysisData(params);
        } else if (SECURITY_METRICS.includes(metric)) {
            // API: DescribeWebProtectionData (DDoS) using CommonClient
            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricNames": [ metric ],
                "ZoneIds": [ "*" ]
            };

            if (interval && interval !== 'auto') {
                params["Interval"] = interval;
            }
            
            // CommonClient setup
            const commonClientConfig = {
                credential: {
                    secretId: secretId,
                    secretKey: secretKey,
                },
                region: "",
                profile: {
                    httpProfile: {
                        endpoint: "teo.tencentcloudapi.com",
                    },
                },
            };

            const commonClient = new CommonClient(
                "teo.tencentcloudapi.com",
                "2022-09-01",
                commonClientConfig
            );

            console.log("Calling DescribeWebProtectionData with params:", JSON.stringify(params, null, 2));
            data = await commonClient.request("DescribeWebProtectionData", params);
            
        } else {
            // API: DescribeTimingL7AnalysisData OR DescribeTimingL7OriginPullData
            params = {
                "StartTime": startTime,
                "EndTime": endTime,
                "MetricNames": [ metric ],
                "ZoneIds": [ "*" ]
            };

            if (interval && interval !== 'auto') {
                params["Interval"] = interval;
            }
            
            console.log("Calling Timing API with params:", JSON.stringify(params, null, 2));
            
            if (ORIGIN_PULL_METRICS.includes(metric)) {
                data = await client.DescribeTimingL7OriginPullData(params);
            } else {
                data = await client.DescribeTimingL7AnalysisData(params);
            }
        }
        
        res.json(data);
    } catch (err) {
        console.error("Error calling Tencent Cloud API:", err);
        res.status(500).json({ error: err.message });
    }
});

export default app;
