package com.ttk.dz.openapi.sdk;

public class DzResultHead {
    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    /**
     * 错误码
     */
   private String errorCode;
    /**
     * 错误信息
     */
   private String errorMsg;





}
