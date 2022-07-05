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

    /**
     * json串方式获取验证码
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject getAuthCodeWithJson(String jsonStringData) {

        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        if (requestBody.getString("userId") == null || !"0".equals(requestBody.getString("userId"))) {
            requestBody.put("userId", "0");
        }
        //2、发送请求
        Map<String, String> headerMap = new HashMap<String, String>();
        return DzHttpUtil.post(apiHost + "/AGG/oauth2/getCode?access_token=" + getAccessToken(), requestBody, headerMap);

    }

    /**
     * 创建企业
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject createOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/AGG/org/create", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    public JSONObject deleteOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/AGG/org/delete", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    public JSONObject getWebUrl(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/AGG/getWebUrl", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    public JSONObject queryOrgDetailInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/AGG/org/queryOrgInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    /**
     * 保存 网报账号信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject saveTaxLoginInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        try {
            if (requestBody.getJSONObject("dlxxDto") != null) {
                String before = requestBody.getJSONObject("dlxxDto").getString("DLMM");
                if (before != null) {
                    //对密码信息加密
                    //由于服务器端用的rest接口，没有加密，所以这里还是需要加密的
                    requestBody.getJSONObject("dlxxDto").put("DLMM", DzOpenApiDesUtil.encryption(before));
                }
            }

            return DzHttpUtil.postRestfulRequest(apiHost + "/AGG/org/tax-login-info/save", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    public JSONObject updateOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/AGG/org/update", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    /**
     * 获取页面访问地址
     *
     * @param page     要访问网页的标识 app name，厂家提供
     * @param orgId    如果是批量相关的接口传null（比如：批量申报页，批量采集页），如果是非批量接口传对应的orgId（比如：企业信息页，申报清册页）
     * @param paramMap 参数map集合，约定好的参数，直接追加到url后面（value值会进行URL encode 编码 ）
     * @return String 完整的单点登录url地址
     */
    public String getWebUrl(String page, String orgId, Map<String, String> paramMap) {
        return getWebUrl(page, orgId, paramMap, appKey);
    }

    public String getWebUrl(String page, String orgId, Map<String, String> paramMap, String targetAppKey) {
        if (page == null || page.isEmpty()) {
            throw new OpenApiBusinessException("", "参数page不能为空");
        }
        StringBuilder urlParamsSb = new StringBuilder();

        if (paramMap != null) {
            for (String key : paramMap.keySet()) {
                urlParamsSb.append("&");
                urlParamsSb.append(key);
                urlParamsSb.append("=");
                try {
                    urlParamsSb.append(URLEncoder.encode(paramMap.get(key), "utf-8"));
                } catch (UnsupportedEncodingException e) {
                    throw new OpenApiBusinessException("", e.getMessage());
                }
            }
        }

        //获取appkey的配置，是ysdj还是电子税局

        JSONObject ttkResultDto = getAuthCode(orgId);
        String infoCode = ttkResultDto.getJSONObject("head").getString("infoCode");
        if ("0".equals(infoCode)) {
            String body = ttkResultDto.getString("value");
            String tmpAppkey = DzStringUtil.isNullOrEmpty(targetAppKey) ? appKey : targetAppKey;
            return webHost + "/#/edfx-app-root/simplelogin?appkey=" + tmpAppkey + "&page=" + page + "&code=" + body + urlParamsSb.toString();
        } else {
            if ("10000".equals(infoCode)) {
                this.token = null;
                throw new OpenApiBusinessException("", "token解析失败，请重试");
            } else {
                this.token = null;
                throw new OpenApiBusinessException("", "获取验证码时遇到错误,错误码:" + infoCode + "；错误信息：" + ttkResultDto.getJSONObject("head").getString("infoMsg"));
            }

        }
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
        Map<String, String> headerMap = new HashMap<String, String>();
        return DzHttpUtil.post(apiHost + "/AGG/oauth2/getCode?access_token=" + getAccessToken(), requestBody, headerMap);

    }

    /**
     * 获取发票
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject fetchInvoice(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        JSONObject jsonObject = null;
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/fetchInvoice", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }

    }

    /**
     * 获取发票，异步获取，能避免发票数量大、网速慢导致的超时问题
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject fetchInvoiceAsync(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            JSONObject jsonObject = DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/collecteDataAsync", getAccessToken(), appSecret, requestBody, null, appKey);
            if (!jsonObject.getJSONObject("result").getBooleanValue("success")) {
                //有异常
                logger.info("采集请求异常");
                return jsonObject;
            } else {
                String seq = jsonObject.getString("value");
                logger.info("采集发票流水号：" + seq);
                requestBody = JSONObject.parseObject("{\"orgId\":" + requestBody.getLong("orgId") + ",\"seq\":" + seq + "}");
                while (true) {
                    //休眠2秒钟
                    TimeUnit.SECONDS.sleep(2);
                    //循环查询结果
                    JSONObject result = DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/asyncRequestResult", getAccessToken(), appSecret, requestBody, null, appKey);
                    if (result.getJSONObject("result").getBooleanValue("success")) {
                        //采集有结果了
                        logger.info("发票采集完毕");
                        return result;
                    } else {
                        if (result.getJSONObject("error").getString("message").contains("请求尚未返回")) {
                            //还没采集完，当前线程休眠2秒钟，然后继续查询结果
                            logger.info("发票采集中");
                        } else {
                            logger.info("发票采集异常");
                            return result;
                        }

                    }
                }
            }
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }

    }

    /**
     * 私有云用
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject fetchInvoiceAsyncForPrivateCloud(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            JSONObject jsonObject = DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/collecteDataAsyncForPrivateCloud", getAccessToken(), appSecret, requestBody, null, appKey);
            if (!jsonObject.getJSONObject("result").getBooleanValue("success")) {
                //有异常
                logger.info("采集请求异常");
                return jsonObject;
            } else {
                String seq = jsonObject.getString("value");
                logger.info("采集发票流水号：" + seq);
                requestBody = JSONObject.parseObject("{\"orgId\":" + requestBody.getLong("orgId") + ",\"seq\":" + seq + "}");
                while (true) {
                    //休眠2秒钟
                    TimeUnit.SECONDS.sleep(2);
                    //循环查询结果
                    JSONObject result = DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/asyncRequestResultForPrivateCloud", getAccessToken(), appSecret, requestBody, null, appKey);
                    if ("0".equals(result.getJSONObject("head").getString("infoCode"))) {
                        //采集有结果了
                        logger.info("发票采集完毕");
                        return result;
                    } else {
                        if (result.getJSONObject("head").getString("infoMsg").contains("请求尚未返回")) {
                            //还没采集完，当前线程休眠2秒钟，然后继续查询结果
                            logger.info("发票采集中");
                        } else {
                            logger.info("发票采集异常");
                            return result;
                        }

                    }
                }
            }
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }

    }

    /**
     * 公有云公布发票查验接口供私有云调用
     *
     * @return
     */
    public JSONObject getInvoiceAsyncForPrivateClound(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            JSONObject jsonObject = DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/getInvoiceAsync", getAccessToken(), appSecret, requestBody, null, appKey);
            if (!jsonObject.getJSONObject("result").getBooleanValue("success")) {
                //有异常
                logger.info("查验请求异常");
                return jsonObject;
            } else {
                String seq = jsonObject.getString("value");
                logger.info("发票查验流水号：" + seq);
                requestBody = JSONObject.parseObject("{\"orgId\":" + requestBody.getLong("orgId") + ",\"seq\":" + seq + "}");
                while (true) {
                    //休眠2秒钟
                    TimeUnit.SECONDS.sleep(2);
                    //循环查询结果
                    JSONObject result = DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/asyncRequestResultForPrivateCloud", getAccessToken(), appSecret, requestBody, null, appKey);
                    if ("0".equals(result.getJSONObject("head").getString("infoCode"))) {
                        //查验有结果了
                        logger.info("发票查验完毕");
                        return result;
                    } else {
                        if (result.getJSONObject("head").getString("infoMsg").contains("请求尚未返回")) {
                            //还没查验完，当前线程休眠2秒钟，然后继续查询结果
                            logger.info("发票查验中");
                        } else {
                            logger.info("发票查验异常");
                            return result;
                        }

                    }
                }
            }
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    /**
     * 批量采集发票
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject collectInvoiceBatch(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/collectBatch", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

//    public JSONObject cj(String jsonParameter) throws OpenApiBusinessException {
//        JSONObject param = JSONObject.parseObject(jsonParameter);
//        if (!param.containsKey("addJob")) {
//            param.put("addJob", true); // 未指定参数时第一次默认发起下载任务
//        }
//
//        boolean hasProcessing = false; // 是否有正在处理中的发票下载任务
//        int retryCount = 12; // 发起下载任务查询结剩余重试次数
//        Map<String, JSONObject> statusMap = new HashMap<>();
//        do {
//            JSONObject cjObj = rest("/FP/getFpxzStatus", param.toJSONString());
//            JSONObject resultObj = cjObj.getJSONObject("result");
//            Boolean success = resultObj.getBoolean("success");
//            if (success == null || !success) {
//                return cjObj;
//            }
//
//            hasProcessing = false;
//            JSONArray valueArray = cjObj.getJSONArray("value");
//            for (Object valueItem : valueArray) {
//                JSONObject valueItemObj = (JSONObject) valueItem;
//                String status = valueItemObj.getString("status");
//                if ("processing".equals(status) || "toProcess".equals(status)) {
//                    hasProcessing = true;
//                }
//                JSONObject temp = new JSONObject();
//                temp.put("status", status);
//                temp.put("msg", valueItemObj.get("msg"));
//                statusMap.put(valueItemObj.getString("jxxbz") + valueItemObj.getString("fplx"), temp);
//            }
//            retryCount--;
//            if (hasProcessing && retryCount >= 0) { // 重试查询结果每次间隔 10s
//                try {
//                    Thread.sleep(10 * 1000L);
//                } catch (InterruptedException ex) {
//                    ex.printStackTrace();
//                }
//                param.put("addJob", false);
//            }
//        } while (hasProcessing && retryCount >= 0);
//
//        JSONObject result = new JSONObject();
//        JSONObject value = new JSONObject();
//        result.put("value", value);
//        JSONArray jxxbzs = param.getJSONArray("jxxbzs");
//        JSONArray fplxs = param.getJSONArray("fplxs");
//        for (Object jxxbz : jxxbzs) {
//            for (Object fplx : fplxs) {
//                String key = "" + jxxbz + fplx;
//                if (!statusMap.containsKey(key)) {
//                    continue; // TODO
//                }
//                JSONObject statusObj = statusMap.get(key);
//                value.put(key , statusObj);
//                String status = statusObj.getString("status");
//                if (!"processed".equals(status)) {
//                    continue;
//                }
//                param.put("jxxbz", jxxbz);
//                param.put("fplx", fplx);
//                JSONObject cjObj = rest("/FP/cj", param.toJSONString());
//                JSONObject resultObj = cjObj.getJSONObject("result");
//                Boolean success = resultObj.getBoolean("success");
//                if (success == null || !success) {
//                    statusObj.put("status", "failed");
//                    statusObj.put("msg", cjObj.getJSONObject("error").getString("message"));
//                    continue;
//                }
//                JSONArray list = cjObj.getJSONObject("value").getJSONArray("list");
//                statusObj.put("list", list);
//            }
//        }
//        return result;
//    }
//
//    public JSONObject cjYgx(String jsonParameter) throws OpenApiBusinessException {
//        JSONObject param = JSONObject.parseObject(jsonParameter);
//        if (!param.containsKey("addJob")) {
//            param.put("addJob", true); // 未指定参数时第一次默认发起下载任务
//        }
//
//        int retryCount = 12; // 发起下载任务查询结剩余重试次数
//        JSONObject statusObj;
//        do {
//            JSONObject cjObj = rest("/FP/getGxgxztStatus", param.toJSONString());
//            JSONObject resultObj = cjObj.getJSONObject("result");
//            Boolean success = resultObj.getBoolean("success");
//            if (success == null || !success) {
//                return cjObj;
//            }
//
//            statusObj = cjObj.getJSONObject("value");
//            String status = statusObj.getString("status");
//            if (!"processing".equals(status) && !"toProcess".equals(status)) {
//                break;
//            }
//            retryCount--;
//            if (retryCount >= 0) { // 重试查询结果每次间隔 10s
//                try {
//                    Thread.sleep(10 * 1000L);
//                } catch (InterruptedException ex) {
//                    ex.printStackTrace();
//                }
//                param.put("addJob", false);
//            }
//        } while (retryCount >= 0);
//
//        JSONObject result = new JSONObject();
//        JSONObject value = new JSONObject();
//        result.put("value", value);
//        JSONArray fplxs = param.getJSONArray("fplxs");
//        for (Object fplx : fplxs) {
//            JSONObject temp = new JSONObject();
//            temp.put("status", statusObj.get("status"));
//            temp.put("msg", statusObj.get("msg"));
//            value.put("" + fplx , temp);
//            String status = temp.getString("status");
//            if (!"processed".equals(status)) {
//                continue;
//            }
//            param.put("fplx", fplx);
//            JSONObject cjObj = rest("/FP/cjYgx", param.toJSONString());
//            JSONObject resultObj = cjObj.getJSONObject("result");
//            Boolean success = resultObj.getBoolean("success");
//            if (success == null || !success) {
//                temp.put("status", "failed");
//                temp.put("msg", cjObj.getJSONObject("error").getString("message"));
//                continue;
//            }
//            JSONArray list = cjObj.getJSONObject("value").getJSONArray("list");
//            temp.put("list", list);
//        }
//        return result;
//    }

    /**
     * 获取发票统计信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryInvoiceSummary(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/invoice/querySummary", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }
    }

    public JSONObject restArray(String path, String jsonParameter) {
        if (path == null) {
            throw new OpenApiBusinessException("", "path不能为空");
        }
        if (jsonParameter == null) {
            throw new OpenApiBusinessException("", "jsonParameter不能为空");
        }

        // 发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + path.trim(), getAccessToken(), appSecret, jsonParameter, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("", e.getMessage());
        }

    }

    /**
     * 获取发票下载任务的状态
     * <p>参数传入 json 字符串
     * <p>参数格式：nsrsbh 企业纳税人识别号，必填
     * <p>kpyfs 开票月份列表，必填，[202104, 202103]，格式yyyyMM
     * <p>jxxbzs 进销项标识列表，必填，jx 进项，xx 销项
     * <p>fplxs 发票类型代码列表，必填
     * <p>addJob 是否发起下载任务，默认不发起
     * <p>第一次调用接口传入 true 发起任务，之后定时调用接口传入 false 获取状态，直到接口返回处理成功或者失败，返回成功调用采集发票接口
     *
     * @param jsonParameter
     * @return 任务状态列表
     * <p>格式 {"jxxbz": "jx", "kpyf": 202104, "fplx": "01", "status": "processed", "msg": ""}
     * <p>任务处理成功的情况 status: processed
     * <p>任务处理失败的情况 status: failed, msg 为失败原因
     * <p>其他情况 toProcess：已发起申请，待处理；processing：处理中；disabled：不支持
     * @throws OpenApiBusinessException
     */
    public JSONArray getFpxzStatus(String jsonParameter) throws OpenApiBusinessException {
        if (DzStringUtil.isNullOrEmpty(jsonParameter)) {
            throw new OpenApiBusinessException("", "参数不能为空");
        }
        JSONObject jsonObj;
        try {
            jsonObj = JSONObject.parseObject(jsonParameter);
        } catch (Exception ex) {
            String msg = "获取发票下载状态失败，接口参数转 json 异常：" + ex.getMessage();
            logger.error(msg, ex);
            throw new OpenApiBusinessException("", msg);
        }
        List<String> invalidList = new ArrayList<>();
        String nsrsbh = jsonObj.getString("nsrsbh");
        if (DzStringUtil.isNullOrEmpty(nsrsbh)) {
            invalidList.add("纳税人识别号");
        }
        JSONArray kpyfs = jsonObj.getJSONArray("kpyfs");
        if (kpyfs == null || kpyfs.isEmpty()) {
            invalidList.add("开票月份列表");
        }
        JSONArray jxxbzs = jsonObj.getJSONArray("jxxbzs");
        if (jxxbzs == null || jxxbzs.isEmpty()) {
            invalidList.add("进销项标识列表");
        }
        JSONArray fplxs = jsonObj.getJSONArray("fplxs");
        if (fplxs == null || fplxs.isEmpty()) {
            invalidList.add("发票类型代码列表");
        }
        if (!invalidList.isEmpty()) {
            throw new OpenApiBusinessException("", DzStringUtil.join(invalidList, "、") + "不能为空");
        }

        boolean addJob = false;
        if (jsonObj.containsKey("addJob")) {
            addJob = jsonObj.getBooleanValue("addJob");
        }
        jsonObj.put("addJob", addJob);
        jsonObj.remove("kpyfs");

        JSONArray result = new JSONArray();
        for (Object kpyf : kpyfs) {
            jsonObj.put("kpyf", kpyf);
            JSONObject fpxzObj = rest("/FP/getFpxzStatus", jsonObj.toJSONString());
            JSONObject fpxzResultObj = fpxzObj.getJSONObject("result");
            Boolean success = fpxzResultObj.getBoolean("success");
            if (success != null && success) {
                result.addAll(fpxzObj.getJSONArray("value"));
            } else {
                String msg = fpxzObj.getJSONObject("error").getString("message");
                Date date = new Date();
                for (Object jxxbz : jxxbzs) {
                    for (Object fplx : fplxs) {
                        JSONObject error = new JSONObject();
                        error.put("jxxbz", jxxbz);
                        error.put("fplx", fplx);
                        error.put("kpyf", kpyf);
                        error.put("status", "failed");
                        error.put("msg", msg);
                        error.put("time", date);
                        result.add(error);
                    }
                }
            }
        }
        return result;
    }

    /**
     * 采集发票
     * <p>参数传入 json 字符串
     * <p>参数格式：nsrsbh 企业纳税人识别号，必填
     * <p>kpyfs 开票月份列表，必填，[202104, 202103]，格式yyyyMM
     * <p>jxxbzs 进销项标识列表，必填，jx 进项，xx 销项
     * <p>fplxs 发票类型代码列表，必填
     *
     * @param jsonParameter
     * @return 发票结果
     * <p>以税款所属期+进销项标识+发票类型（例如202104_jx_01）为 key 的 map
     * <p>value 格式 {"result": true/false, "list": [], "msg": ""}
     * <p>采集成功 result: true, list 为对应的发票列表
     * <p>采集失败 result: false, msg 为失败原因
     * @throws OpenApiBusinessException
     */
    public JSONObject cj(String jsonParameter) throws OpenApiBusinessException {
        if (DzStringUtil.isNullOrEmpty(jsonParameter)) {
            throw new OpenApiBusinessException("", "参数不能为空");
        }
        JSONObject jsonObj;
        try {
            jsonObj = JSONObject.parseObject(jsonParameter);
        } catch (Exception ex) {
            String msg = "采集发票失败，接口参数转 json 异常：" + ex.getMessage();
            logger.error(msg, ex);
            throw new OpenApiBusinessException("", msg);
        }
        List<String> invalidList = new ArrayList<>();
        String nsrsbh = jsonObj.getString("nsrsbh");
        if (DzStringUtil.isNullOrEmpty(nsrsbh)) {
            invalidList.add("纳税人识别号");
        }
        JSONArray kpyfs = jsonObj.getJSONArray("kpyfs");
        if (kpyfs == null || kpyfs.isEmpty()) {
            invalidList.add("开票月份列表");
        }
        JSONArray jxxbzs = jsonObj.getJSONArray("jxxbzs");
        if (jxxbzs == null || jxxbzs.isEmpty()) {
            invalidList.add("进销项标识列表");
        }
        JSONArray fplxs = jsonObj.getJSONArray("fplxs");
        if (fplxs == null || fplxs.isEmpty()) {
            invalidList.add("发票类型代码列表");
        }
        if (!invalidList.isEmpty()) {
            throw new OpenApiBusinessException("", DzStringUtil.join(invalidList, "、") + "不能为空");
        }
        JSONObject result = new JSONObject();
        jsonObj.remove("kpyfs");
        jsonObj.remove("jxxbzs");
        jsonObj.remove("fplxs");
        for (Object kpyf : kpyfs) {
            jsonObj.put("kpyf", kpyf);
            for (Object jxxbz : jxxbzs) {
                jsonObj.put("jxxbz", jxxbz);
                for (Object fplx : fplxs) {
                    jsonObj.put("fplx", fplx);
                    String key = "" + kpyf + "_" + jxxbz + "_" + fplx;
                    JSONObject cjObj = rest("/FP/cj", jsonObj.toJSONString());
                    JSONObject cjResultObj = cjObj.getJSONObject("result");
                    Boolean success = cjResultObj.getBoolean("success");
                    JSONObject item = new JSONObject();
                    if (success != null && success) {
                        JSONArray list = cjObj.getJSONObject("value").getJSONArray("list");
                        item.put("result", true);
                        item.put("list", list);
                    } else {
                        String msg = cjObj.getJSONObject("error").getString("message");
                        item.put("result", false);
                        item.put("msg", msg);
                    }
                    result.put(key, item);
                }
            }
        }
        return result;
    }

    /**
     * 获取更新勾选状态任务的状态
     * <p>参数传入 json 字符串
     * <p>参数格式：nsrsbh 企业纳税人识别号，必填
     * <p>skssqs 税款所属期列表，必填，[202104, 202103]，格式yyyyMM
     *
     * @param jsonParameter
     * @return 任务状态列表
     * <p>格式 {"skssq": 202104, "status": "processed", "msg": ""}
     * <p>任务处理成功的情况 status: processed
     * <p>任务处理失败的情况 status: failed, msg 为失败原因
     * <p>其他情况 toProcess：已发起申请，待处理；processing：处理中；disabled：不支持
     * @throws OpenApiBusinessException
     */
    public JSONArray getGxgxztStatus(String jsonParameter) throws OpenApiBusinessException {
        if (DzStringUtil.isNullOrEmpty(jsonParameter)) {
            throw new OpenApiBusinessException("", "参数不能为空");
        }
        JSONObject jsonObj;
        try {
            jsonObj = JSONObject.parseObject(jsonParameter);
        } catch (Exception ex) {
            String msg = "获取更新发票勾选状态失败，接口参数转 json 异常：" + ex.getMessage();
            logger.error(msg, ex);
            throw new OpenApiBusinessException("", msg);
        }
        List<String> invalidList = new ArrayList<>();
        String nsrsbh = jsonObj.getString("nsrsbh");
        if (DzStringUtil.isNullOrEmpty(nsrsbh)) {
            invalidList.add("纳税人识别号");
        }
        JSONArray skssqs = jsonObj.getJSONArray("skssqs");
        if (skssqs == null || skssqs.isEmpty()) {
            invalidList.add("税款所属期列表");
        }
        if (!invalidList.isEmpty()) {
            throw new OpenApiBusinessException("", DzStringUtil.join(invalidList, "、") + "不能为空");
        }

        boolean addJob = false;
        if (jsonObj.containsKey("addJob")) {
            addJob = jsonObj.getBooleanValue("addJob");
        }
        jsonObj.put("addJob", addJob);
        jsonObj.remove("skssqs");

        JSONArray result = new JSONArray();
        for (Object skssq : skssqs) {
            jsonObj.put("skssq", skssq);
            JSONObject gxgxztObj = rest("/FP/getGxgxztStatus", jsonObj.toJSONString());
            JSONObject gxgxztResultObj = gxgxztObj.getJSONObject("result");
            Boolean success = gxgxztResultObj.getBoolean("success");
            if (success != null && success) {
                JSONObject item = gxgxztObj.getJSONObject("value");
                result.add(item);
            } else {
                String msg = gxgxztObj.getJSONObject("error").getString("message");
                Date date = new Date();
                JSONObject error = new JSONObject();
                error.put("status", "failed");
                error.put("msg", msg);
                error.put("time", date);
                error.put("skssq", skssq);
                result.add(error);
            }
        }
        return result;
    }

    /**
     * 采集已勾选发票，支持多税款所属期
     * <p>参数传入 json 字符串
     * <p>参数格式：nsrsbh 企业纳税人识别号，必填
     * <p>skssqs 税款所属期列表，必填，[202104, 202103]，格式yyyyMM
     * <p>fplxs 发票类型代码列表，必填，["01", "03", "14", "17"]
     *
     * @param jsonParameter
     * @return 发票结果
     * <p>以税款所属期+发票类型（例如202104_01）为 key 的 map
     * <p>value 格式 {"result": true/false, "list": [], "msg": ""}
     * <p>采集成功 result: true, list 为对应的发票列表
     * <p>采集失败 result: false, msg 为失败原因
     * @throws OpenApiBusinessException
     */
    public JSONObject cjYgx(String jsonParameter) throws OpenApiBusinessException {
        if (DzStringUtil.isNullOrEmpty(jsonParameter)) {
            throw new OpenApiBusinessException("", "参数不能为空");
        }
        JSONObject jsonObj;
        try {
            jsonObj = JSONObject.parseObject(jsonParameter);
        } catch (Exception ex) {
            String msg = "采集发票失败，接口参数转 json 异常：" + ex.getMessage();
            logger.error(msg, ex);
            throw new OpenApiBusinessException("", msg);
        }
        List<String> invalidList = new ArrayList<>();
        String nsrsbh = jsonObj.getString("nsrsbh");
        if (DzStringUtil.isNullOrEmpty(nsrsbh)) {
            invalidList.add("纳税人识别号");
        }
        JSONArray skssqs = jsonObj.getJSONArray("skssqs");
        if (skssqs == null || skssqs.isEmpty()) {
            invalidList.add("税款所属期列表");
        }
        JSONArray fplxs = jsonObj.getJSONArray("fplxs");
        if (fplxs == null || fplxs.isEmpty()) {
            invalidList.add("发票类型代码列表");
        }
        if (!invalidList.isEmpty()) {
            throw new OpenApiBusinessException("", DzStringUtil.join(invalidList, "、") + "不能为空");
        }
        jsonObj.remove("skssqs");
        jsonObj.remove("fplxs");

        JSONObject result = new JSONObject();
        for (Object skssq : skssqs) {
            jsonObj.put("skssq", skssq);
            for (Object fplx : fplxs) {
                jsonObj.put("fplx", fplx);
                String key = "" + skssq + "_" + fplx;
                JSONObject item = new JSONObject();
                JSONObject cjObj = rest("/FP/cjYgx", jsonObj.toJSONString());
                JSONObject cjResultObj = cjObj.getJSONObject("result");
                Boolean success = cjResultObj.getBoolean("success");
                if (success != null && success) {
                    JSONArray list = cjObj.getJSONObject("value").getJSONArray("list");
                    item.put("result", true);
                    item.put("list", list);
                } else {
                    String msg = cjObj.getJSONObject("error").getString("message");
                    item.put("result", false);
                    item.put("msg", msg);
                }
                result.put(key, item);
            }
        }
        return result;
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

    /**
     * token 解析错误代码情况下 清除本地token缓存
     *
     * @param jsonObject
     */
    private void clearLocalToken(JSONObject jsonObject) {
        if (jsonObject != null && jsonObject.getJSONObject("head") != null) {
            if ("10000".equals(jsonObject.getJSONObject("head").getString("infoCode"))) {
                this.token = null;
            }
        }
    }
}
