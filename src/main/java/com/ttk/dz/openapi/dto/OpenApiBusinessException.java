package com.ttk.dz.openapi.dto;

public class OpenApiBusinessException extends RuntimeException {
	/**
	 *
	 */
	private static final long serialVersionUID = -4368873598973127606L;
	private final String code;
	private Exception innerException = null;
	private Object data;
	private Type type;

	public enum Type {
		error,		//对应于前端的红叉提示
		warning		//对应于前端的黄叹号提示
	}

	public OpenApiBusinessException(String code, String message) {
		super(message);
		this.code = code;
		this.data = null;
	}

	public OpenApiBusinessException(String code, String message, Type type) {
		super(message);
		this.code = code;
		this.data = null;
		this.type = type;
	}

	public OpenApiBusinessException(String code, String message, Object data, Exception ex) {

        super(message);
		this.code = code; 
		this.data = data;
		this.innerException = ex;
	} 
	
	public Exception getInnerException() {
		return innerException;
	}
	public Object getData() {
		return data;
	}
	public OpenApiBusinessException setData(Object data) {
		this.data = data;
		return this;
	}
	public OpenApiBusinessException setInnerException(Exception ex) {
		this.innerException = ex;
		return this;
	}
	public String getCode() {
		return code;
	}

	public Type getType() {
		return type;
	}

	public void setType(Type type) {
		this.type = type;
	}
}
