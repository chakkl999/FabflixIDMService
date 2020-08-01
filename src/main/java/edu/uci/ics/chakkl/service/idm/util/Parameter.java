package edu.uci.ics.chakkl.service.idm.util;

public class Parameter {
    private int type;
    private Object object;

    Parameter(int type, Object object)
    {
        this.type = type;
        this.object = object;
    }

    public static Parameter createParameter(int type, Object object)
    {
        return new Parameter(type, object);
    }

    public int getType() {
        return type;
    }

    public Object getObject() {
        return object;
    }
}
