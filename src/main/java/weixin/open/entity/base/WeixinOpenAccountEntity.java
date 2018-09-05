package weixin.open.entity.base;

import java.util.Date;

public class WeixinOpenAccountEntity implements java.io.Serializable{
    /**
     * 主键
     */
    private java.lang.String id;
    /**
     * appid
     */
    private java.lang.String appid;
    /**
     * 第三方平台推送 : ticket
     */
    private java.lang.String ticket;

    private Date getTicketTime;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAppid() {
        return appid;
    }

    public void setAppid(String appid) {
        this.appid = appid;
    }

    public String getTicket() {
        return ticket;
    }

    public void setTicket(String ticket) {
        this.ticket = ticket;
    }

    public Date getGetTicketTime() {
        return getTicketTime;
    }

    public void setGetTicketTime(Date getTicketTime) {
        this.getTicketTime = getTicketTime;
    }
}
