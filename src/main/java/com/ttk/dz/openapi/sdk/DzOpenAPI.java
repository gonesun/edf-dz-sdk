package com.ttk.dz.openapi.sdk;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.ttk.dz.openapi.dto.OpenApiBusinessException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class DzOpenAPI {

    private static Log logger = LogFactory.getLog(DzOpenAPI.class);
    /**
     * api 网关主机地址
     */
    private String apiHost;


    /**
     * 嵌入网页打开地址
     */
    private String webHost;
    /**
     * 应用key
     */
    private String appKey;
    /**
     * 应用密钥
     */
    private String appSecret;

    /**
     * md5后的密钥
     */
    //private String appSecretMD5;
    /**
     * 应用级访问令牌
     */
    private volatile String token;

    /**
     * token有效期，毫秒，15天有效期
     */
    private volatile Long expiresIn;

    /**
     * 刷新token用
     */
    private volatile String refreshToken;
    /**
     * token获取时间
     */
    private Long lastTokenTime;

    public DzOpenAPI(String apiHost, String appKey, String appSecret, String webHost) {
        if (DzStringUtil.isNullOrEmpty(apiHost)) {
            throw new OpenApiBusinessException("", "参数apiHost不正确");
        }
        if (DzStringUtil.isNullOrEmpty(appKey)) {
            throw new OpenApiBusinessException("", "参数appKey不正确");
        }
        if (DzStringUtil.isNullOrEmpty(appSecret)) {
            throw new OpenApiBusinessException("", "参数appSecret不正确");
        }
        //if (DzStringUtil.isNullOrEmpty(webHost)) {
        //    throw new OpenApiBusinessException("","参数webHost不正确");
        //}
        if (apiHost.endsWith("/")) {
            apiHost = apiHost.substring(0, apiHost.length() - 1);
        }
        if (webHost.endsWith("/")) {
            webHost = webHost.substring(0, webHost.length() - 1);
        }
        this.apiHost = apiHost;
        this.appKey = appKey;
        this.appSecret = appSecret;
        this.webHost = webHost;
        //this.appSecretMD5 = DzHttpUtil.MD5(appSecret);
    }

    /**
     * 通用接口
     *
     * @param path          请求url ，举例：/GDS/taxReport/queryRequiredTaxTables ，/GDS/basicData/createOrg
     * @param jsonParameter 参数json串
     * @return JSONObject
     */
    public JSONObject rest(String path, String jsonParameter) {
        if (path == null) {
            throw new OpenApiBusinessException("", "path不能为空");
        }
        if (jsonParameter == null) {
            throw new OpenApiBusinessException("", "jsonParameter不能为空");
        }


        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonParameter);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + path.trim(), getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }

    }

    /**
     * 获取应用级访问token
     */
    private String getAccessToken() {
        if (DzStringUtil.isNullOrEmpty(token)) {
            synchronized (this) {
                if (DzStringUtil.isNullOrEmpty(token)) {
                    //获取新token
                    newToken();
                }
            }
        } else {
            //验证有效期，如果快到有效期则刷新token，如果超了有效期则重新获取token
            Long currentTime = System.currentTimeMillis();
            //token持有时间
            Long holdingTime = currentTime - lastTokenTime;
            //到期前24~2小时内 均可刷新token
            if (holdingTime >= (expiresIn - 3600 * 24 * 1000) && holdingTime <= (expiresIn - 3600 * 2 * 1000)) {
                synchronized (this) {
                    //刷新token
                    refreshToken();
                }
            } else if (holdingTime > (expiresIn - 3600 * 2 * 1000)) {
                synchronized (this) {
                    //获取新token
                    newToken();
                }

            }
        }
        return token;
    }

    /**
     * 获取新token
     */
    private void newToken() {
        //1、body数据准备
        JSONObject requestBody = new JSONObject();
        requestBody.put("grant_type", "client_credentials");
        requestBody.put("client_appkey", appKey);
//        requestBody.put("client_secret", appSecret);
        requestBody.put("client_secret", DzHttpUtil.MD5(appSecret));
        //2、发送请求
        JSONObject jsonObject = DzHttpUtil.post(apiHost + "/edf/oauth2/access_token", requestBody, null);
        //3、解析返回结果
        if (jsonObject == null) {
            throw new OpenApiBusinessException("", "获取token失败，请确认网址" + apiHost + " 是否能正常访问！");
        }
        JSONObject jsonObjectBody = jsonObject.getJSONObject("body");
        if (jsonObjectBody.get("error_msg") != null) {
            throw new OpenApiBusinessException("", jsonObjectBody.get("error_msg").toString());
        }
        token = jsonObjectBody.getString("access_token");
        expiresIn = jsonObjectBody.getLong("expires_in");
        lastTokenTime = System.currentTimeMillis();
        refreshToken = jsonObjectBody.getString("refresh_token");
    }

    /**
     * 刷新token
     */
    private void refreshToken() {
        //refresh_token
        //1、body数据准备
        JSONObject requestBody = new JSONObject();
        requestBody.put("grant_type", "refresh_token");
        requestBody.put("refresh_token", refreshToken);
        //2、发送请求
        JSONObject jsonObject = DzHttpUtil.post(apiHost + "/AGG/oauth2/login", requestBody, null);
        //3、解析返回结果
        JSONObject jsonObjectBody = jsonObject.getJSONObject("value");
        if (jsonObjectBody.get("info_msg") != null) {
            throw new OpenApiBusinessException("", jsonObjectBody.get("info_msg").toString());
        }
        token = jsonObjectBody.getString("access_token");
        expiresIn = jsonObjectBody.getLong("expires_in");
        lastTokenTime = System.currentTimeMillis();
        refreshToken = jsonObjectBody.getString("refresh_token");
    }

    public String getApiHost() {
        return apiHost;
    }

    public void setApiHost(String apiHost) {
        this.apiHost = apiHost;
    }

    public String getWebHost() {
        return webHost;
    }

    public void setWebHost(String webHost) {
        this.webHost = webHost;
    }

    public String getAppKey() {
        return appKey;
    }

    public void setAppKey(String appKey) {
        this.appKey = appKey;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public void setAppSecret(String appSecret) {
        this.appSecret = appSecret;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

}
