package com.ttk.dz.openapi.sdk;

import com.alibaba.fastjson.JSONObject;
import com.ttk.dz.openapi.dto.OpenApiBusinessException;

import java.util.HashMap;
import java.util.Map;

public class DzOpenAPI {
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

    public DzOpenAPI(String apiHost, String appKey, String appSecret) {
        if (DzStringUtil.isNullOrEmpty(apiHost)) {
            throw new OpenApiBusinessException("", "参数apiHost不正确");
        }
        if (DzStringUtil.isNullOrEmpty(appKey)) {
            throw new OpenApiBusinessException("", "参数appKey不正确");
        }
        if (DzStringUtil.isNullOrEmpty(appSecret)) {
            throw new OpenApiBusinessException("", "参数appSecret不正确");
        }
        this.apiHost = DzStringUtil.formatUrl(apiHost);
        this.appKey = appKey;
        this.appSecret = appSecret;
    }

    public DzOpenAPI(String apiHost, String appKey, String appSecret, String webHost) {
        this(apiHost, appKey, appSecret);
        if (DzStringUtil.isNullOrEmpty(webHost)) {
            throw new OpenApiBusinessException("","参数webHost不正确");
        }
        this.webHost = DzStringUtil.formatUrl(webHost);
    }

    /**
     * 通用接口
     *
     * @param path          请求url ，举例：/GDS/basicData/createOrg
     * @param jsonParameter 参数json串
     * @return JSONObject
     */
    public JSONObject rest(String path, String jsonParameter) {
        if (DzStringUtil.isNullOrEmpty(path)) {
            throw new OpenApiBusinessException("", "请求地址不能为空");
        }
        if (DzStringUtil.isNullOrEmpty(jsonParameter)) {
            throw new OpenApiBusinessException("", "请求参数不能为空");
        }
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonParameter);
        if(path.equals(ConstCode.webUrl)){
            return getWebUrl(path, requestBody);
        }
        //2、发送请求
        try {
            String url = apiHost + path.trim();
            return DzHttpUtil.postRestfulRequest(url, getAccessToken(), appSecret, requestBody);
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
            long holdingTime = currentTime - lastTokenTime;
            //到期前24~2小时内 均可刷新token
            if (holdingTime >= (expiresIn - ConstCode.oneHour * 24) && holdingTime <= (expiresIn - ConstCode.oneHour * 2)) {
                synchronized (this) {
                    //刷新token
                    refreshToken();
                }
            } else if (holdingTime > (expiresIn - ConstCode.oneHour * 2)) {
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
        requestBody.put("client_appkey", this.appKey);
        requestBody.put("client_secret", DzHttpUtil.MD5(appSecret));
        //2、发送请求
        String url = apiHost + ConstCode.accessToken;
        JSONObject jsonObject = DzHttpUtil.post(url, requestBody, null);
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
        String url = apiHost + ConstCode.accessToken;
        JSONObject jsonObject = DzHttpUtil.post(url, requestBody, null);
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

    /**
     * 获取验证码
     *
     * @param orgId orgId
     * @return JSONObject
     */
    public JSONObject getAuthCode(String orgId) {
        //1、body数据准备
        JSONObject requestBody = new JSONObject();
        requestBody.put("userId", "0");
        requestBody.put("orgId", orgId);
        //2、发送请求
        Map<String, String> headerMap = new HashMap<>();
        return DzHttpUtil.post(apiHost + "/edf/oauth2/getAuthCode?access_token=" + getAccessToken(), requestBody, headerMap);
    }

    /**
     * 获取页面访问地址
     *
     * @param path         请求url :/api/getWebUrl
     * @param requestBody 参数
     * @return JSONObject
     */
    private JSONObject getWebUrl(String path, JSONObject requestBody) {
        //2、发送请求
        try {
            JSONObject ttkResultDto = getAuthCode(requestBody.getString("orgId"));
            String errorCode = ttkResultDto.getJSONObject("head").getString("errorCode");
            if ("0".equals(errorCode)) {
                requestBody.put("code", ttkResultDto.getString("body"));
            }
            requestBody.put("webHost", webHost);
            requestBody.put("appKey", appKey);
            return DzHttpUtil.postRestfulRequest(apiHost + path.trim(), getAccessToken(), appSecret, requestBody, null);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
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
