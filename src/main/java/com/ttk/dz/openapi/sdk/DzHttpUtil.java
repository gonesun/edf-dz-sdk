package com.ttk.dz.openapi.sdk;

import com.alibaba.fastjson.JSONObject;
import com.ttk.dz.openapi.dto.OpenApiBusinessException;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;

class DzHttpUtil {

    private static String sdkVersion = null;

    /**
     * 读取sdk版本号
     */
    static {
        try {
            ResourceBundle resource = ResourceBundle.getBundle("sdk");
            if (resource != null) {
                sdkVersion = resource.getString("sdkVersion");
            }
        } catch (Exception e) {
            sdkVersion = "";
        }
    }

    static JSONObject post(String url, JSONObject requestBody, Map<String, String> map) {
        return post(url, requestBody.toJSONString(), map);
    }

    private static JSONObject post(String url, String requestBody, Map<String, String> map) {
        if (url == null || url.isEmpty()) {
            throw new OpenApiBusinessException("","url不能为空");
        }
        if (requestBody == null) {
            throw new OpenApiBusinessException("","requestBody不能为null");
        }
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(url);

        // 定制header参数
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-Type", "application/json");
        if (sdkVersion == null) {
            sdkVersion = "";
        }
        httpPost.setHeader("sdkVersion", sdkVersion);
        // 添加通用参数
        if (map != null) {
            Iterator<Map.Entry<String, String>> iterator = map.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, String> entry = iterator.next();
                httpPost.setHeader(entry.getKey(), entry.getValue());
            }
        }
        // 请求体body
        StringEntity entity = new StringEntity(requestBody, StandardCharsets.UTF_8);
        httpPost.setEntity(entity);
        CloseableHttpResponse httpResponse = null;
        try {
            // 开始网络请求
            httpResponse = httpClient.execute(httpPost);
            // 响应状态码
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            if(statusCode != 200){
                throw new OpenApiBusinessException("","rest请求失败，(" + url + ")状态码：" + statusCode);
            }
            HttpEntity httpEntity = httpResponse.getEntity();
            String res_body_string = EntityUtils.toString(httpEntity, StandardCharsets.UTF_8);
            return JSONObject.parseObject(res_body_string);
        } catch (Exception e) {
            throw new OpenApiBusinessException("","rest请求过程中有异常发生：" + e.getMessage());
        } finally {
            try {
                if (httpResponse != null) {
                    httpResponse.close();
                }
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (Exception e) {
                throw new OpenApiBusinessException("","http关闭时有异常发生：" + e.getMessage());
            }
        }

    }

    /**
     * 业务数据签名
     * @param url url
     * @param access_token token
     * @param appSecret appSecret
     * @param requestBodyData requestBodyData
     * @param header header
     * @param appKey
     * @return 对象
     * @throws NoSuchAlgorithmException 算法异常
     */
    static JSONObject postRestfulRequest(String url, String access_token, String appSecret,
                                         JSONObject requestBodyData, Map<String, String> header, String appKey) throws NoSuchAlgorithmException {
        return postRestfulRequest(url, access_token, appSecret, requestBodyData.toJSONString(), header, appKey);
    }
    static JSONObject postRestfulRequest(String url, String access_token, String appSecret, JSONObject requestBodyData) throws NoSuchAlgorithmException {
        return postRestfulRequest(url, access_token, appSecret, requestBodyData.toJSONString(), null, null);
    }

    private static JSONObject postRestfulRequest(String url, String access_token, String appSecret,
                                                 String requestBodyData, Map<String, String> header, String appKey) throws NoSuchAlgorithmException {
        if (url == null || url.isEmpty()) {
            throw new OpenApiBusinessException("","url不能为空");
        }
        if (access_token == null || access_token.isEmpty()) {
            throw new OpenApiBusinessException("","access_token不能为空");
        }
        if (appSecret == null || appSecret.isEmpty()) {
            throw new OpenApiBusinessException("","appSecret不能为空");
        }
        url = DzStringUtil.formatUrl(url);
        // 签名准备
        long timestamp = System.currentTimeMillis();
        // 签名前
        String strToSign = "access_token=" + access_token + "&timestamp=" + timestamp + "&" + requestBodyData + "{" + appSecret + "}";
        // 签名
        String sign = MD5(strToSign).toUpperCase();
        // header里额外参数
        if (header == null) {
            header = new HashMap<>();
        }
        header.put("access_token", access_token);
        header.put("timestamp", String.valueOf(timestamp));
        header.put("sign", sign);

        // 发送请求
        JSONObject jsonObject = post(url, requestBodyData, header);

        // 得到结果
        return jsonObject;
    }

    /**
     * 计算MD5值
     * @param sourceStr sourceStr
     * @return sourceStr
     */
    static String MD5(String sourceStr) {
        String result = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(sourceStr.getBytes(StandardCharsets.UTF_8));
            byte b[] = md.digest();
            int i;
            StringBuilder buf = new StringBuilder();
            for (byte aB : b) {
                i = aB;
                if (i < 0) {
                    i += 256;
                }
                if (i < 16) {
                    buf.append("0");
                }

                buf.append(Integer.toHexString(i));
            }
            result = buf.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
        return result;
    }

}
