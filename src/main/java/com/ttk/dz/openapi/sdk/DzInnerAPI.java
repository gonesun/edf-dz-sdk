package com.ttk.dz.openapi.sdk;

import com.alibaba.fastjson.JSONObject;
import com.ttk.dz.openapi.dto.OpenApiBusinessException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class DzInnerAPI {
    private static Log logger = LogFactory.getLog(DzInnerAPI.class);

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

    public DzInnerAPI(String apiHost, String appKey, String appSecret, String webHost) {
        if (DzStringUtil.isNullOrEmpty(apiHost)) {
            throw new OpenApiBusinessException("","参数apiHost不正确");
        }
        if (DzStringUtil.isNullOrEmpty(appKey)) {
            throw new OpenApiBusinessException("","参数appKey不正确");
        }
        if (DzStringUtil.isNullOrEmpty(appSecret)) {
            throw new OpenApiBusinessException("","参数appSecret不正确");
        }
        if (DzStringUtil.isNullOrEmpty(webHost)) {
            throw new OpenApiBusinessException("","参数webHost不正确");
        }
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
        //requestBody.put("client_secret", appSecretMD5);
        requestBody.put("client_secret", DzHttpUtil.MD5(appSecret));
        //2、发送请求
        JSONObject jsonObject = DzHttpUtil.post(apiHost + "/AGG/oauth2/login", requestBody, null);
        //3、解析返回结果
        if (jsonObject == null) {
            throw new OpenApiBusinessException("","获取token失败，请确认网址" + apiHost + " 是否能正常访问！");
        }
        JSONObject jsonObjectBody = jsonObject.getJSONObject("value");
        if (jsonObjectBody.get("info_msg") != null) {
            throw new OpenApiBusinessException("",jsonObjectBody.get("info_msg").toString());
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
            throw new OpenApiBusinessException("",jsonObjectBody.get("info_msg").toString());
        }
        token = jsonObjectBody.getString("access_token");
        expiresIn = jsonObjectBody.getLong("expires_in");
        lastTokenTime = System.currentTimeMillis();
        refreshToken = jsonObjectBody.getString("refresh_token");
    }

    /**
     * 保存纳企业税基本信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject saveNsxx(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/saveNsxx", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 网报账号是否已验证通过
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject hasReadSJInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/hasReadSJInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 保存 网报账号信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject saveTaxLoginInfoForPrivateCloud(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        try {
            if (requestBody.getJSONObject("dlxxDto") != null) {
                String before = requestBody.getJSONObject("dlxxDto").getString("DLMM");
                if (before != null) {
                    //对密码信息加密
                    requestBody.getJSONObject("dlxxDto").put("DLMM", DzOpenApiDesUtil.encryption(before));
                }
            }

            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/saveTaxLoginInfoForPrivateCloud", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {

            return null;
        }
    }

    /**
     * 查询企业详细信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryOrgDetailInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/queryOrgDetailInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    /**
     * 上传税报数据 xml数据格式
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject writeValueAddedTaxXmlData(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/writeValueAddedTaxXmlData", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 获取报税结果
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject getTaxResult(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/getTaxResult", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }

    }



    /**
     * 获取发票
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryWuXianYiJin(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        JSONObject jsonObject = null;
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/queryWuXianYiJin", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }

    }

    /**
     * 查询地区是否支持发票汇总
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject isAreaSupportInvoice(String jsonStringData) {
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/isAreaSupportInvoice", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    /**
     * 设置税报默认取数方式
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject setDefaultTaxReportAccessType(String jsonStringData) {
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/setDefaultTaxReportAccessType", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    /**
     * 设置各税种取数方式
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject saveTaxReportAccessType(String jsonStringData) {
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/saveTaxReportAccessType", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 查询各税种取数方式
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryTaxReportAccessTypeList(String jsonStringData) {
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/queryTaxReportAccessTypeList", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 获取税务申报表XML
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject downloadTaxReportXML(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/downloadTaxReportXML", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }

    }

    /**
     * 获取税务申报表PDF
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject downloadTaxReportPDF(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/downloadTaxReportPDF", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }

    }

    /**
     * 获取必填表单名单信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryRequiredTaxTables(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/queryRequiredTaxTables", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 查询纳税人未缴税款信息查询
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryUnpaidInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/taxReport/queryUnpaidInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject createUsersAndOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/createUsersAndOrg", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject updateUserRole(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/updateUserRole", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    public JSONObject queryWorkbenchTotalInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/queryWorkbenchTotalInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject queryWorkbenchDetailInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/queryWorkbenchDetailInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject calendarQuery(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/calendarQuery", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject createBatchUser(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/createBatchUser", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject updateUserEnable(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/updateUserEnable", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject updateJcyyCustomOrgState(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/updateJcyyCustomOrgState", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    public JSONObject updateUser(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/updateUser", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    public JSONObject queryOrgBaseInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/queryOrgBaseInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 通过该接口查询客户申报进度信息
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryDeclarationProgress(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/queryDeclarationProgress", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 给金财代账的代理机构批量添加用户
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject createDljgUsersForDzgl(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/createDljgUsersForDzgl", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 通过该接口修改企业报税是否全部完成状态
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject finishDeclaration(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/finishDeclaration", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 删除ES客户企业
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject deleteCustomerOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/deleteCustomerOrg", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 初始化ES客户企业检测
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject canInitializeCustomerOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/canInitializeCustomerOrg", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 同步客户账套名称
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject syncCustomerOrgName(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);

        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/syncCustomerOrgName", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    public JSONObject queryMenuForDzgl(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/queryMenuForDzgl", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    /**
     * 获取报税的饼图数据
     * 2019-03-25 14:29
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     * @author huangzhong
     */
    public JSONObject getEntryChartDtoForTax(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/getEntryChartDtoForTax", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 获取报税明细数据
     * 2019-03-25 14:29
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     * @author huangzhong
     */
    public JSONObject getTaxHandleStatusList(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/getTaxHandleStatusList", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 获取报税状态数据
     * 2019-05-15 14:29
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     * @author huangzhong
     */
    public JSONObject getTaxClosedStatusList(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/basicData/getTaxClosedStatusList", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 修改web代账的代理机构
     *
     */
    public JSONObject updateEsDljgOrg(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/GDS/es/updateEsDljgOrg", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 获取会计准则和申报周期
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject queryFinancialDeclarationBasicInfo(String jsonStringData) {
        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/SB/taxReport/queryFinancialDeclarationBasicInfo", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }


    /**
     * 上传财报数据
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject writeFinancialReportData(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/SB/taxReport/writeFinancialReportData", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

    /**
     * 上传税报数据
     *
     * @param jsonStringData jsonStringData
     * @return JSONObject
     */
    public JSONObject writeValueAddedTaxData(String jsonStringData) {

        //1、body数据准备
        JSONObject requestBody = JSONObject.parseObject(jsonStringData);
        //2、发送请求
        try {
            return DzHttpUtil.postRestfulRequest(apiHost + "/SB/taxReport/writeValueAddedTaxData", getAccessToken(), appSecret, requestBody, null, appKey);
        } catch (Exception e) {
            throw new OpenApiBusinessException("",e.getMessage());
        }
    }

}
